import {
  officialAcpRegistryIconUrlForAgentId,
  ProviderDriverKind,
  resolveOfficialAcpRegistryIconUrl,
  TextGenerationError,
  type AcpRegistryOperationError,
  type AcpRegistryProbeModel,
  type CustomModelSetting,
  type ProviderOptionDescriptor,
  type ServerProvider,
  type ServerProviderModel,
} from "@t3tools/contracts";
import { AcpRegistrySettings } from "../settings.ts";
import * as HostProcess from "@t3tools/shared/HostProcess";
import { createModelCapabilities } from "@t3tools/shared/model";
import * as Clock from "effect/Clock";
import * as Digest from "effect/crypto/Digest";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Equal from "effect/Equal";
import * as FileSystem from "effect/FileSystem";
import * as Option from "effect/Option";
import * as Path from "effect/Path";
import * as Ref from "effect/Ref";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import * as Semaphore from "effect/Semaphore";
import * as ChildProcessSpawner from "effect/process/ChildProcessSpawner";

import * as ProviderHost from "@t3tools/provider-core/server/ProviderHost";
import { AcpRegistryAdapterV2Driver, type AcpRegistryAdapterV2DriverEnv } from "./adapter.ts";
import type { ProviderTextGeneration } from "@t3tools/provider-core/server/textGeneration";
import { ProviderDriverError } from "@t3tools/provider-core/server/errors";
import { makeManagedServerProvider } from "@t3tools/provider-core/server/managedProvider";
import { mergeProviderInstanceEnvironment } from "@t3tools/provider-core/server/instanceEnvironment";
import {
  defaultProviderContinuationIdentity,
  type ProviderDriver,
  type ProviderInstance,
} from "@t3tools/provider-core/server/driver";
import {
  providerModelsFromSettings,
  providerProbeEnvironment,
} from "@t3tools/provider-core/server/snapshotProbe";
import { makeManualOnlyProviderMaintenanceCapabilities } from "@t3tools/provider-core/server/maintenanceResolver";
import {
  haveProviderSnapshotSettingsChanged,
  makeProviderSnapshotSettingsSource,
  type ProviderSnapshotSettings,
} from "@t3tools/provider-core/server/snapshotSettings";
import {
  type AcpRegistryAvailableCommands,
  type AcpRegistryConfigurationProbe,
  type AcpRegistryConfigurationProbeInput,
  type AcpRegistryConfigurationProbeResult,
  type AcpRegistryLiveConfiguration,
  deleteAcpRegistrySession,
  disableAcpRegistryProvider,
  listAcpRegistrySessions,
  listAcpRegistryProviders,
  logoutAcpRegistry,
  probeAcpRegistryConfiguration,
  setAcpRegistryProvider,
} from "./probe.ts";
import * as AcpRegistrySupport from "./AcpRegistrySupport.ts";
import * as AcpRegistryRuntimeCoordinator from "./AcpRegistryRuntimeCoordinator.ts";
import * as AcpRegistryAuth from "./auth.ts";
import * as AcpRegistryAuthenticationState from "./authenticationState.ts";

const DRIVER_KIND = ProviderDriverKind.make("acpRegistry");
const decodeSettings = Schema.decodeSync(AcpRegistrySettings);
// Cache only successful authenticated probes so sign-in changes remain visible.
const PROBE_SUCCESS_TTL_MS = 15 * 60 * 1_000;
const PROBE_PROVISIONAL_TTL_MS = 30 * 1_000;
const MODEL_DISCOVERY_RETRY_MS = 60_000;

function acpRegistryProbeTtlMs(provider: ServerProvider): number {
  const discoveredModels = provider.models.filter((model) => !model.isCustom);
  return discoveredModels.length <= 1 ? PROBE_PROVISIONAL_TTL_MS : PROBE_SUCCESS_TTL_MS;
}

interface AcpRegistryEnrichmentCache {
  readonly generation: number;
  readonly entry: {
    readonly provider: ServerProvider;
    readonly expiresAt: number;
  } | null;
}

export function isAcpRegistryCacheValid(
  entry: NonNullable<AcpRegistryEnrichmentCache["entry"]>,
  inspectedVersion: string | null,
  local: boolean,
  now: number,
): boolean {
  return (
    entry.expiresAt > now &&
    ((local && inspectedVersion === null) || entry.provider.version === inspectedVersion)
  );
}

export function updateAcpRegistryEnrichmentCache(input: {
  readonly cache: AcpRegistryEnrichmentCache;
  readonly configuration: AcpRegistryLiveConfiguration;
  readonly customModels: ReadonlyArray<CustomModelSetting>;
  readonly now: number;
}): AcpRegistryEnrichmentCache {
  const { cache, configuration, customModels, now } = input;
  if (cache.entry === null) {
    // No probe has landed yet, but the live session published its
    // configuration to the snapshot. Advance the cache epoch so a probe that
    // was still in flight cannot overwrite that newer state when it lands.
    return { ...cache, generation: cache.generation + 1 };
  }
  const provider = applyAcpRegistryLiveConfiguration(
    cache.entry.provider,
    configuration,
    customModels,
  );
  if (Equal.equals(provider, cache.entry.provider)) return cache;
  return {
    ...cache,
    // The live session advanced the provider past what an in-flight probe
    // started from; bump the epoch so the probe discards its stale result
    // instead of overwriting this entry and publishing it.
    generation: cache.generation + 1,
    entry: {
      ...cache.entry,
      provider,
      expiresAt: now + acpRegistryProbeTtlMs(provider),
    },
  };
}
const EMPTY_CAPABILITIES = createModelCapabilities({ optionDescriptors: [] });
type AcpModelObservations = ReadonlyMap<
  string,
  { readonly descriptors: ReadonlyArray<ProviderOptionDescriptor>; readonly observedAt: number }
>;

function modelOptionDescriptors(configuration: AcpRegistryLiveConfiguration) {
  const ids = new Set(configuration.modelOptionIds);
  return configuration.configOptions.filter((descriptor) => ids.has(descriptor.id));
}

function updateModelObservations(
  previous: AcpModelObservations,
  configuration: AcpRegistryLiveConfiguration,
  now: number,
  beforeProbe: AcpModelObservations = previous,
  pruneCatalog = false,
): AcpModelObservations {
  const next = new Map(previous);
  if (pruneCatalog && configuration.models.length > 0) {
    const ids = new Set(configuration.models.map((model) => model.id));
    for (const id of next.keys()) {
      if (!ids.has(id) && previous.get(id) === beforeProbe.get(id)) next.delete(id);
    }
  }
  for (const model of configuration.models) {
    if (
      model.reasoningEffort === undefined ||
      previous.get(model.id) !== beforeProbe.get(model.id)
    ) {
      continue;
    }
    const own = (previous.get(model.id)?.descriptors ?? []).filter(
      (descriptor) => descriptor.type !== "select" || descriptor.role !== "reasoning",
    );
    next.set(model.id, {
      descriptors: model.reasoningEffort === null ? own : [...own, model.reasoningEffort],
      observedAt: now,
    });
  }
  const model = configuration.currentModelId;
  if (
    model !== null &&
    configuration.configOptionsKnown !== false &&
    previous.get(model) === beforeProbe.get(model)
  ) {
    next.set(model, { descriptors: modelOptionDescriptors(configuration), observedAt: now });
  }
  return next;
}

function withObservedModelOptions(
  provider: ServerProvider,
  observations: AcpModelObservations,
  customModels: ReadonlyArray<CustomModelSetting>,
  previous: AcpModelObservations = observations,
): ServerProvider {
  if (observations.size === 0) return provider;
  const explicitCustom = new Set(
    customModels.flatMap((model) =>
      typeof model === "object" && model.capabilities != null ? [model.slug] : [],
    ),
  );
  return {
    ...provider,
    models: provider.models.map((model) => {
      if (model.isCustom && explicitCustom.has(model.slug)) return model;
      const options = observations.get(model.slug)?.descriptors;
      if (options === undefined) return model;
      const scopedIds = new Set(
        [...options, ...(previous.get(model.slug)?.descriptors ?? [])].map(
          (descriptor) => descriptor.id,
        ),
      );
      const shared = (model.capabilities?.optionDescriptors ?? []).filter(
        (descriptor) =>
          !scopedIds.has(descriptor.id) &&
          (descriptor.type !== "select" || descriptor.role !== "reasoning"),
      );
      const capabilities = createModelCapabilities({ optionDescriptors: [...shared, ...options] });
      return { ...model, capabilities };
    }),
  };
}
const MAINTENANCE = makeManualOnlyProviderMaintenanceCapabilities({
  provider: DRIVER_KIND,
  packageName: null,
});

const makeUnsupportedTextGeneration = (): ProviderTextGeneration => {
  const unsupported = (operation: string) =>
    Effect.fail(
      new TextGenerationError({
        operation,
        detail: "ACP Registry instances do not provide application text generation.",
      }),
    );
  return {
    generateCommitMessage: () => unsupported("generateCommitMessage"),
    generatePrContent: () => unsupported("generatePrContent"),
    generateBranchName: () => unsupported("generateBranchName"),
    generateThreadTitle: () => unsupported("generateThreadTitle"),
    generateReviewGuide: () => unsupported("generateReviewGuide"),
    generateTranscriptionPostProcessing: () => unsupported("generateTranscriptionPostProcessing"),
  };
};

function modelsFromDiscovery(
  discovery:
    | Pick<
        AcpRegistryLiveConfiguration,
        "models" | "currentModelId" | "configOptions" | "modelOptionIds" | "configOptionsKnown"
      >
    | undefined,
  customModels: ReadonlyArray<CustomModelSetting>,
  previousModels: ReadonlyArray<ServerProviderModel> = [],
): ReadonlyArray<ServerProviderModel> {
  const discovered = discovery?.models ?? [];
  const capabilities =
    discovery === undefined || discovery.configOptions.length === 0
      ? EMPTY_CAPABILITIES
      : createModelCapabilities({ optionDescriptors: discovery.configOptions });
  // Model-specific options describe only the session's current model; other
  // models keep the shared ones plus what an earlier session reported for them.
  const modelOptionIds = new Set(discovery?.modelOptionIds ?? []);
  const shared = (discovery?.configOptions ?? []).filter(
    (descriptor) => !modelOptionIds.has(descriptor.id),
  );
  const sharedIds = new Set(shared.map((descriptor) => descriptor.id));
  const capabilitiesFor = ({ id: slug, reasoningEffort }: AcpRegistryProbeModel) => {
    if (slug === discovery?.currentModelId && discovery.configOptionsKnown !== false) {
      return capabilities;
    }
    // The levels a model advertises replace the ones an earlier session reported.
    const own = (
      previousModels.find((model) => model.slug === slug)?.capabilities?.optionDescriptors ?? []
    ).filter(
      (descriptor) =>
        !sharedIds.has(descriptor.id) &&
        (reasoningEffort === undefined ||
          descriptor.type !== "select" ||
          descriptor.role !== "reasoning"),
    );
    const optionDescriptors = [...shared, ...own, ...(reasoningEffort ? [reasoningEffort] : [])];
    return optionDescriptors.length === 0
      ? EMPTY_CAPABILITIES
      : createModelCapabilities({ optionDescriptors });
  };
  const builtInModels: ReadonlyArray<ServerProviderModel> =
    discovered.length === 0
      ? [
          {
            slug: "default",
            name: "Default",
            isCustom: false,
            isDefault: true,
            capabilities,
          },
        ]
      : discovered.map((model) => ({
          slug: model.id,
          name: model.name,
          isCustom: false,
          ...(model.id === discovery?.currentModelId ? { isDefault: true } : {}),
          capabilities: capabilitiesFor(model),
        }));
  return providerModelsFromSettings(
    builtInModels,
    customModels,
    createModelCapabilities({ optionDescriptors: shared }),
  );
}

function acpRegistrySnapshotReadiness(
  inspection:
    | AcpRegistrySupport.AcpRegistryInspection
    | { readonly status: "failed"; readonly message: string },
): Pick<ServerProvider, "installed" | "version" | "status" | "message"> {
  switch (inspection.status) {
    case "ready":
      return { installed: true, version: inspection.version, status: "ready" };
    case "unconfigured":
      return {
        installed: false,
        version: null,
        status: "warning",
        message:
          "Select an ACP Registry agent or configure a local ACP executable before starting a thread.",
      };
    case "not_found":
      return {
        installed: false,
        version: null,
        status: "error",
        message: `ACP Registry does not contain agent '${inspection.agentId}'.`,
      };
    case "unsupported":
      return {
        installed: false,
        version: inspection.version,
        status: "error",
        message: `ACP Registry agent '${inspection.agentId}' has no compatible distribution for this environment.`,
      };
    case "missing_runner":
      return {
        installed: false,
        version: inspection.version,
        status: "error",
        message:
          inspection.distribution === "local"
            ? "Local ACP executable is not available on this environment's PATH."
            : `ACP executable '${inspection.runner}' is not available on this environment's PATH.`,
      };
    case "unprepared":
      return {
        installed: false,
        version: inspection.version,
        status: "warning",
        message: `ACP Registry agent '${inspection.agentId}' has not been prepared on this environment.`,
      };
    case "failed":
      return {
        installed: false,
        version: null,
        status: "error",
        message: inspection.message,
      };
  }
}

interface SnapshotIdentity {
  readonly instanceId: ProviderInstance["instanceId"];
  readonly displayName: string | undefined;
  readonly accentColor: string | undefined;
  readonly continuationKey: string;
}

function baseSnapshot(
  input: SnapshotIdentity & {
    readonly settings: AcpRegistrySettings;
    readonly checkedAt: string;
    readonly installed: boolean;
    readonly version: string | null;
    readonly status: ServerProvider["status"];
    readonly auth: ServerProvider["auth"];
    readonly documentationUrl?: string;
    readonly message?: string;
    readonly probe?: AcpRegistryConfigurationProbeResult;
    readonly probeError?: AcpRegistryOperationError;
  },
): ServerProvider {
  const iconUrl =
    input.settings.source === "local"
      ? null
      : (resolveOfficialAcpRegistryIconUrl(input.probe?.probe.icon) ??
        officialAcpRegistryIconUrlForAgentId(input.settings.agentId));
  return {
    instanceId: input.instanceId,
    driver: DRIVER_KIND,
    ...(input.displayName ? { displayName: input.displayName } : {}),
    ...(input.accentColor ? { accentColor: input.accentColor } : {}),
    ...(iconUrl ? { iconUrl } : {}),
    continuation: { groupKey: input.continuationKey },
    supportsTextGeneration: false,
    enabled: input.settings.enabled,
    installed: input.installed,
    version: input.version,
    status: input.settings.enabled ? input.status : "disabled",
    auth: { ...input.auth, canLogout: input.auth.canLogout ?? false },
    checkedAt: input.checkedAt,
    setup: {
      canInstall: false,
      ...(input.documentationUrl ? { documentationUrl: input.documentationUrl } : {}),
      canAuthenticate:
        input.installed &&
        (input.probe
          ? input.probe.probe.authMethods.length > 0
          : input.settings.source === "local"
            ? (input.probeError?.authMethods?.length ?? 0) > 0
            : input.settings.agentId.length > 0),
    },
    ...(input.message ? { message: input.message } : {}),
    models: modelsFromDiscovery(
      input.probe?.configuration ?? input.probe?.probe,
      input.settings.customModels,
    ),
    ...(input.probe === undefined
      ? {}
      : {
          nativeSessions: {
            canList: input.probe.probe.sessionManagement.canList,
            canLoad: input.probe.probe.sessionManagement.canLoad,
            canResume: input.probe.probe.sessionManagement.canResume,
            canDelete: input.probe.probe.sessionManagement.canDelete,
            ...(input.probe.canDiscoverModelOptions === true
              ? { canDiscoverModelOptions: true }
              : {}),
          },
          configurableProviders: input.probe.probe.sessionManagement.canConfigureProviders,
        }),
    slashCommands: input.probe?.slashCommands ?? [],
    skills: input.probe?.skills ?? [],
  };
}

export function applyAcpRegistryAvailableCommands(
  provider: ServerProvider,
  commands: Option.Option<AcpRegistryAvailableCommands>,
): ServerProvider {
  return Option.match(commands, {
    onNone: () => provider,
    onSome: ({ slashCommands, skills }) => ({ ...provider, slashCommands, skills }),
  });
}

export function applyAcpRegistryLiveConfiguration(
  provider: ServerProvider,
  configuration: AcpRegistryLiveConfiguration,
  customModels: ReadonlyArray<CustomModelSetting>,
  previousModels: ReadonlyArray<ServerProviderModel> = provider.models,
): ServerProvider {
  const { message: _staleProbeMessage, ...snapshot } = provider;
  // session/load may omit models (Kimi returns `{}`); keep the probed list
  // and apply any live option descriptors to it.
  const probedModels = provider.models.filter((model) => !model.isCustom);
  // A cold-start session can report one placeholder model before its catalog
  // settles, while the probe may already have observed the full catalog. A
  // single model enumerated by an explicit select is not that fallback but
  // the agent's deliberate statement, so it wins over the probe catalog.
  const liveCatalogIsProvisional =
    configuration.models.length === 1 &&
    !configuration.modelsFromModelSelect &&
    probedModels.length > 1;
  const useLiveCatalog =
    configuration.models.length > 1 ||
    (configuration.models.length === 1 && !liveCatalogIsProvisional);
  const selectedProbedModelId =
    configuration.currentModelId !== null &&
    probedModels.some((model) => model.slug === configuration.currentModelId)
      ? configuration.currentModelId
      : (probedModels.find((model) => model.isDefault)?.slug ?? null);
  const discovery = useLiveCatalog
    ? configuration
    : {
        ...configuration,
        models: probedModels.map((model) => ({
          id: model.slug,
          name: model.name,
          description: null,
        })),
        currentModelId: configuration.currentModelId,
      };
  return {
    ...snapshot,
    status: provider.enabled ? "ready" : provider.status,
    models:
      !useLiveCatalog && configuration.configOptions.length === 0
        ? withAcpRegistryDefaultModel(provider.models, selectedProbedModelId)
        : withAcpRegistryDefaultModel(
            modelsFromDiscovery(
              discovery,
              customModels,
              previousModels.filter((model) => !model.isCustom),
            ),
            useLiveCatalog ? configuration.currentModelId : selectedProbedModelId,
          ),
  };
}

function withAcpRegistryDefaultModel(
  models: ReadonlyArray<ServerProviderModel>,
  currentModelId: string | null,
): ReadonlyArray<ServerProviderModel> {
  if (currentModelId === null) return models;
  let changed = false;
  const next = models.map((model) => {
    if (model.isCustom) return model;
    const isDefault = model.slug === currentModelId;
    if ((model.isDefault ?? false) === isDefault) return model;
    changed = true;
    const { isDefault: _previous, ...rest } = model;
    return isDefault ? { ...rest, isDefault: true } : rest;
  });
  return changed ? next : models;
}

function applyAcpRegistryUrlAuthAction(
  provider: ServerProvider,
  action: Option.Option<NonNullable<ServerProvider["auth"]["action"]>>,
): ServerProvider {
  const { action: _previousAction, ...auth } = provider.auth;
  return {
    ...provider,
    auth: Option.match(action, {
      onNone: () => auth,
      onSome: (nextAction) => ({ ...auth, action: nextAction }),
    }),
  };
}

const buildInitialAcpRegistrySnapshot = Effect.fn("AcpRegistryDriver.buildInitialSnapshot")(
  function* (input: SnapshotIdentity & { readonly settings: AcpRegistrySettings }) {
    const checkedAt = DateTime.formatIso(yield* DateTime.now);
    return baseSnapshot({
      ...input,
      checkedAt,
      installed: false,
      version: null,
      status: "warning",
      auth: { status: "unknown" },
      message: input.settings.enabled
        ? "Checking ACP Registry agent readiness..."
        : "ACP Registry is disabled in T3 Code settings.",
    });
  },
);

export function buildCheckedAcpRegistrySnapshot(
  input: SnapshotIdentity & {
    readonly settings: AcpRegistrySettings;
    readonly checkedAt: string;
    readonly inspection:
      | AcpRegistrySupport.AcpRegistryInspection
      | { readonly status: "failed"; readonly message: string };
    readonly probe?: AcpRegistryConfigurationProbeResult;
    readonly probeError?: AcpRegistryOperationError;
  },
): ServerProvider {
  const readiness = acpRegistrySnapshotReadiness(input.inspection);
  const probeFailed = input.probeError !== undefined;
  const advertisedAuthMethod =
    input.probeError?.reason === "authentication_failed"
      ? (input.probeError.authMethods?.find(
          (method) => method.id === input.settings.authMethodId,
        ) ?? input.probeError.authMethods?.[0])
      : undefined;
  const authenticationMessage = advertisedAuthMethod
    ? advertisedAuthMethod.type === "terminal" && advertisedAuthMethod.command
      ? `Sign in in provider settings using "${advertisedAuthMethod.name}". The login terminal runs on this environment.`
      : advertisedAuthMethod.type === "env_var" &&
          (advertisedAuthMethod.envVarNames?.length ?? 0) > 0
        ? `Set ${advertisedAuthMethod.envVarNames!.join(", ")} under this instance's environment variables in provider settings. T3 Code will detect it on the next provider refresh.`
        : `Sign in in provider settings using "${advertisedAuthMethod.name}".`
    : undefined;
  return baseSnapshot({
    ...input,
    ...(input.inspection.status === "ready" && input.inspection.documentationUrl
      ? { documentationUrl: input.inspection.documentationUrl }
      : {}),
    installed: readiness.installed,
    version:
      input.settings.source === "local"
        ? (input.probe?.probe.agentVersion ?? readiness.version)
        : readiness.version,
    // Failed discovery is a warning: an installed agent may still run real turns.
    status: probeFailed ? "warning" : readiness.status,
    auth: input.probe
      ? {
          // Discovery sessions and an empty auth-method list do not prove sign-in.
          status: "unknown",
          canLogout: input.probe.probe.sessionManagement.canLogout,
        }
      : input.probeError?.reason === "authentication_failed"
        ? {
            status: "unauthenticated",
            ...(advertisedAuthMethod
              ? { type: advertisedAuthMethod.type, label: advertisedAuthMethod.name }
              : {}),
            ...(input.probeError.authAction === undefined
              ? {}
              : { action: input.probeError.authAction }),
          }
        : { status: "unknown" },
    ...(input.probeError
      ? { message: authenticationMessage ?? input.probeError.message }
      : readiness.message
        ? { message: readiness.message }
        : {}),
  });
}

export const checkAcpRegistryProviderStatus = Effect.fn("AcpRegistryDriver.checkProviderStatus")(
  function* <Requirements>(
    input: SnapshotIdentity & {
      readonly settings: AcpRegistrySettings;
      readonly cwd: string;
      readonly environment: NodeJS.ProcessEnv;
    },
    probeConfiguration: AcpRegistryConfigurationProbe<Requirements>,
    onDiscovered?: (result: AcpRegistryConfigurationProbeResult) => Effect.Effect<void>,
  ): Effect.fn.Return<ServerProvider, never, AcpRegistrySupport.AcpRegistryCatalog | Requirements> {
    const checkedAt = DateTime.formatIso(yield* DateTime.now);
    if (!input.settings.enabled) {
      return yield* buildInitialAcpRegistrySnapshot(input);
    }
    const catalog = yield* AcpRegistrySupport.AcpRegistryCatalog;
    const inspected = yield* Effect.result(catalog.inspect(input.settings, input.environment));
    if (Result.isFailure(inspected)) {
      return buildCheckedAcpRegistrySnapshot({
        ...input,
        checkedAt,
        inspection: {
          status: "failed",
          message: `Could not inspect ACP Registry agent: ${inspected.failure.message}`,
        },
      });
    }
    if (inspected.success.status !== "ready") {
      return buildCheckedAcpRegistrySnapshot({
        ...input,
        checkedAt,
        inspection: inspected.success,
      });
    }
    const probed = yield* Effect.result(
      probeConfiguration({
        instanceId: input.instanceId,
        settings: input.settings,
        cwd: input.cwd,
        environment: providerProbeEnvironment(input.environment),
      }),
    );
    if (Result.isSuccess(probed)) yield* onDiscovered?.(probed.success) ?? Effect.void;
    return Result.isFailure(probed)
      ? buildCheckedAcpRegistrySnapshot({
          ...input,
          checkedAt,
          inspection: inspected.success,
          probeError: probed.failure,
        })
      : buildCheckedAcpRegistrySnapshot({
          ...input,
          checkedAt,
          inspection: inspected.success,
          probe: probed.success,
        });
  },
);

export const checkAcpRegistryProviderReadiness = Effect.fn(
  "AcpRegistryDriver.checkProviderReadiness",
)(function* (
  input: SnapshotIdentity & {
    readonly settings: AcpRegistrySettings;
    readonly environment: NodeJS.ProcessEnv;
  },
): Effect.fn.Return<ServerProvider, never, AcpRegistrySupport.AcpRegistryCatalog> {
  const checkedAt = DateTime.formatIso(yield* DateTime.now);
  if (!input.settings.enabled) {
    return yield* buildInitialAcpRegistrySnapshot(input);
  }
  const catalog = yield* AcpRegistrySupport.AcpRegistryCatalog;
  const inspected = yield* Effect.result(catalog.inspect(input.settings, input.environment));
  const snapshot = buildCheckedAcpRegistrySnapshot({
    ...input,
    checkedAt,
    inspection: Result.isFailure(inspected)
      ? {
          status: "failed",
          message: `Could not inspect ACP Registry agent: ${inspected.failure.message}`,
        }
      : inspected.success,
  });
  return inspected._tag === "Success" && inspected.success.status === "ready"
    ? {
        ...snapshot,
        message: "Checking ACP authentication, models, and commands in the background...",
      }
    : snapshot;
});

export type AcpRegistryDriverEnv =
  | AcpRegistryAdapterV2DriverEnv
  | Digest.Digest
  | ProviderHost.ProviderHost;

export const AcpRegistryDriver: ProviderDriver<AcpRegistrySettings, AcpRegistryDriverEnv> = {
  driverKind: DRIVER_KIND,
  metadata: {
    displayName: "ACP Registry",
    supportsMultipleInstances: true,
    hasDefaultInstance: false,
  },
  configSchema: AcpRegistrySettings,
  defaultConfig: () => decodeSettings({}),
  create: Effect.fn("AcpRegistryDriver.create")(function* ({
    instanceId,
    displayName,
    accentColor,
    environment,
    enabled,
    config,
  }) {
    const catalog = yield* AcpRegistrySupport.AcpRegistryCatalog;
    const runtimeCoordinator = yield* Effect.serviceOption(
      AcpRegistryRuntimeCoordinator.AcpRegistryRuntimeCoordinator,
    );
    if (Option.isSome(runtimeCoordinator)) {
      yield* runtimeCoordinator.value.clearAvailableCommands(instanceId);
      yield* runtimeCoordinator.value.clearLiveConfiguration(instanceId);
      yield* Effect.addFinalizer(() =>
        runtimeCoordinator.value
          .clearAvailableCommands(instanceId)
          .pipe(Effect.andThen(runtimeCoordinator.value.clearLiveConfiguration(instanceId))),
      );
    }
    const random = yield* SecureRandom.SecureRandom;
    const spawner = yield* ChildProcessSpawner.ChildProcessSpawner;
    const fileSystem = yield* FileSystem.FileSystem;
    const path = yield* Path.Path;
    const hostEnvironment = yield* HostProcess.Environment;
    const host = yield* ProviderHost.ProviderHost;
    const continuationIdentity = defaultProviderContinuationIdentity({
      driverKind: DRIVER_KIND,
      instanceId,
    });
    const identity = {
      instanceId,
      displayName,
      accentColor,
      continuationKey: continuationIdentity.continuationKey,
    };
    const effectiveConfig = { ...config, enabled } satisfies AcpRegistrySettings;
    const processEnvironment = yield* mergeProviderInstanceEnvironment(
      environment,
      hostEnvironment,
    );
    const orchestrationAdapter = yield* AcpRegistryAdapterV2Driver.create({
      instanceId,
      displayName,
      accentColor,
      environment,
      enabled,
      config,
    }).pipe(
      Effect.mapError(
        (cause) =>
          new ProviderDriverError({
            driver: DRIVER_KIND,
            instanceId,
            detail: "Failed to build ACP Registry orchestration adapter.",
            cause,
          }),
      ),
    );
    const readinessInput = {
      ...identity,
      settings: effectiveConfig,
      environment: processEnvironment,
    };
    const confirmedAuthentication =
      yield* AcpRegistryAuthenticationState.makeAcpRegistryAuthenticationState({
        cacheDir: host.paths.providerStatusCacheDir,
        instanceId,
        settings: effectiveConfig,
        environment,
        processEnvironment,
      });
    const modelObservations = yield* Ref.make<AcpModelObservations>(new Map());
    const modelDiscoveryGeneration = yield* Ref.make(0);
    const failedModelDiscovery = new Map<string, number>();
    let appliedLiveConfiguration: AcpRegistryLiveConfiguration | undefined;
    let unsupportedDiscoveryUntil = 0;
    const resetModelDiscovery = Ref.update(modelDiscoveryGeneration, (current) => current + 1).pipe(
      Effect.tap(() =>
        Effect.sync(() => {
          failedModelDiscovery.clear();
          unsupportedDiscoveryUntil = 0;
        }),
      ),
    );
    const clearLearnedModels = resetModelDiscovery.pipe(
      Effect.andThen(Ref.set(modelObservations, new Map())),
    );
    const projectModelOptions = (provider: ServerProvider) =>
      Ref.get(modelObservations).pipe(
        Effect.map((observations) =>
          withObservedModelOptions(provider, observations, effectiveConfig.customModels),
        ),
      );
    const withLiveRuntimeState = Effect.fn("AcpRegistryDriver.withLiveRuntimeState")(function* (
      input: ServerProvider,
    ) {
      if (input.auth.status === "unauthenticated") {
        yield* confirmedAuthentication.set(false);
        yield* clearLearnedModels;
        if (Option.isSome(runtimeCoordinator)) {
          yield* runtimeCoordinator.value.clearLiveConfiguration(instanceId);
        }
        return input;
      }
      const provider =
        input.enabled &&
        input.installed &&
        input.auth.status === "unknown" &&
        (yield* confirmedAuthentication.get)
          ? { ...input, auth: { ...input.auth, status: "authenticated" as const } }
          : input;
      if (Option.isNone(runtimeCoordinator)) return yield* projectModelOptions(provider);
      return yield* Effect.all({
        commands: runtimeCoordinator.value.getAvailableCommands(instanceId),
        configuration: runtimeCoordinator.value.getLiveConfiguration(instanceId),
        authAction: runtimeCoordinator.value.getUrlAuthAction(instanceId),
      }).pipe(
        Effect.flatMap(({ commands, configuration, authAction }) => {
          const withCommands = applyAcpRegistryAvailableCommands(provider, commands);
          return Option.match(input.nativeSessions === undefined ? configuration : Option.none(), {
            onNone: () => Effect.succeed(withCommands),
            onSome: (liveConfiguration) =>
              Effect.succeed(
                applyAcpRegistryLiveConfiguration(
                  withCommands,
                  liveConfiguration,
                  effectiveConfig.customModels,
                  [],
                ),
              ),
          }).pipe(
            Effect.map((withConfiguration) =>
              applyAcpRegistryUrlAuthAction(withConfiguration, authAction),
            ),
          );
        }),
        Effect.flatMap(projectModelOptions),
      );
    });
    // A local executable's version comes only from probing it, so readiness checks reuse the last report.
    const reportedLocalVersion = yield* Ref.make<string | null>(null);
    const checkProvider = checkAcpRegistryProviderReadiness(readinessInput).pipe(
      Effect.provideService(AcpRegistrySupport.AcpRegistryCatalog, catalog),
      Effect.flatMap((provider) =>
        Ref.get(reportedLocalVersion).pipe(
          Effect.map((version) =>
            provider.installed && provider.version === null && version !== null
              ? { ...provider, version }
              : provider,
          ),
        ),
      ),
      Effect.flatMap(withLiveRuntimeState),
    );
    const probeConfiguration = (input: AcpRegistryConfigurationProbeInput) =>
      probeAcpRegistryConfiguration(input).pipe(
        Effect.provideService(AcpRegistrySupport.AcpRegistryCatalog, catalog),
        Effect.provideService(ChildProcessSpawner.ChildProcessSpawner, spawner),
        Effect.provideService(FileSystem.FileSystem, fileSystem),
        Effect.provideService(Path.Path, path),
        Effect.provideService(SecureRandom.SecureRandom, random),
      );
    const probeInput = {
      ...readinessInput,
      cwd: host.paths.cwd,
      environment: providerProbeEnvironment(processEnvironment),
    };
    const probeCoordinationKey =
      effectiveConfig.source === "local" ? `local:${instanceId}` : effectiveConfig.agentId;
    const enrichmentCache = yield* Ref.make<AcpRegistryEnrichmentCache>({
      generation: 0,
      entry: null,
    });
    const liveSnapshotSemaphore = yield* Semaphore.make(1);
    let observedAgentVersion: string | undefined;
    const invalidateEnrichmentCache = Ref.update(enrichmentCache, (current) => ({
      generation: current.generation + 1,
      entry: null,
    }));
    const enrichProviderCached = Effect.fn("AcpRegistryDriver.enrichProviderCached")(function* (
      baseSnapshot: ServerProvider,
    ) {
      const now = yield* Clock.currentTimeMillis;
      const cacheState = yield* Ref.get(enrichmentCache);
      const cached = cacheState.entry;
      if (
        cached !== null &&
        isAcpRegistryCacheValid(
          cached,
          baseSnapshot.version,
          effectiveConfig.source === "local",
          now,
        )
      ) {
        return {
          provider: { ...cached.provider, checkedAt: baseSnapshot.checkedAt },
          generation: cacheState.generation,
        };
      }
      const beforeProbe = yield* Ref.get(modelObservations);
      const enriched = yield* checkAcpRegistryProviderStatus(
        probeInput,
        probeConfiguration,
        (result) =>
          liveSnapshotSemaphore.withPermit(
            Effect.gen(function* () {
              if ((yield* Ref.get(enrichmentCache)).generation !== cacheState.generation) return;
              if (result.configuration === undefined) return;
              const version = result.probe.agentVersion ?? baseSnapshot.version ?? undefined;
              const versionChanged =
                version !== undefined &&
                observedAgentVersion !== undefined &&
                observedAgentVersion !== version;
              if (versionChanged) yield* clearLearnedModels;
              observedAgentVersion = version ?? observedAgentVersion;
              const now = yield* Clock.currentTimeMillis;
              yield* Ref.update(modelObservations, (current) =>
                updateModelObservations(
                  current,
                  result.configuration!,
                  now,
                  versionChanged ? current : beforeProbe,
                  true,
                ),
              );
            }),
          ),
      ).pipe(Effect.provideService(AcpRegistrySupport.AcpRegistryCatalog, catalog));
      if (effectiveConfig.source === "local" && enriched.status === "ready") {
        yield* Ref.set(reportedLocalVersion, enriched.version);
      }
      if (enriched.status === "ready") {
        const completedAt = yield* Clock.currentTimeMillis;
        yield* Ref.update(enrichmentCache, (current) =>
          current.generation === cacheState.generation
            ? {
                ...current,
                entry: {
                  provider: enriched,
                  expiresAt: completedAt + acpRegistryProbeTtlMs(enriched),
                },
              }
            : current,
        );
      }
      return { provider: enriched, generation: cacheState.generation };
    });
    const snapshotSettings = yield* makeProviderSnapshotSettingsSource(effectiveConfig);
    const snapshot = yield* makeManagedServerProvider<
      ProviderSnapshotSettings<AcpRegistrySettings>
    >({
      resolveMaintenance: () => Effect.succeed(MAINTENANCE),
      getSettings: snapshotSettings.getSettings,
      streamSettings: snapshotSettings.streamSettings,
      haveSettingsChanged: haveProviderSnapshotSettingsChanged,
      // Inspection may fetch the registry when its disk cache is missing; creation must not wait on that.
      initialSnapshot: () => buildInitialAcpRegistrySnapshot(readinessInput),
      checkProvider,
      enrichSnapshot: Effect.fn("enrichSnapshot")(function ({
        snapshot,
        getSnapshot,
        publishSnapshot,
      }) {
        if (!snapshot.installed) return Effect.void;
        const publishEnrichment = (
          Option.isSome(runtimeCoordinator)
            ? runtimeCoordinator.value.runBackgroundProbe(
                probeCoordinationKey,
                enrichProviderCached(snapshot),
              )
            : enrichProviderCached(snapshot).pipe(Effect.asSome)
        ).pipe(
          Effect.flatMap(
            Option.match({
              onNone: () => Effect.void,
              onSome: ({ provider, generation }) =>
                liveSnapshotSemaphore.withPermit(
                  Ref.get(enrichmentCache).pipe(
                    Effect.flatMap((current) =>
                      current.generation === generation
                        ? withLiveRuntimeState(provider).pipe(Effect.flatMap(publishSnapshot))
                        : Effect.void,
                    ),
                  ),
                ),
            }),
          ),
        );
        if (Option.isNone(runtimeCoordinator)) return publishEnrichment;

        const publishLiveCommands = runtimeCoordinator.value.watchAvailableCommands(
          instanceId,
          ({ slashCommands, skills }) =>
            liveSnapshotSemaphore.withPermit(
              getSnapshot.pipe(
                Effect.flatMap((current) =>
                  publishSnapshot({
                    ...current,
                    slashCommands,
                    skills,
                  }),
                ),
              ),
            ),
        );
        const publishLiveConfiguration = runtimeCoordinator.value.watchLiveConfiguration(
          instanceId,
          (configuration) =>
            liveSnapshotSemaphore.withPermit(
              Effect.suspend(() => {
                if (configuration === appliedLiveConfiguration) return Effect.void;
                appliedLiveConfiguration = configuration;
                return Effect.all({ current: getSnapshot, now: Clock.currentTimeMillis }).pipe(
                  Effect.flatMap(({ current, now }) =>
                    Ref.modify(modelObservations, (before) => {
                      const next = updateModelObservations(before, configuration, now);
                      return [
                        withObservedModelOptions(
                          applyAcpRegistryLiveConfiguration(
                            current,
                            configuration,
                            effectiveConfig.customModels,
                            [],
                          ),
                          next,
                          effectiveConfig.customModels,
                          before,
                        ),
                        next,
                      ];
                    }),
                  ),
                  Effect.tap(() =>
                    Clock.currentTimeMillis.pipe(
                      Effect.flatMap((now) =>
                        Ref.update(enrichmentCache, (cache) =>
                          updateAcpRegistryEnrichmentCache({
                            cache,
                            configuration,
                            customModels: effectiveConfig.customModels,
                            now,
                          }),
                        ),
                      ),
                    ),
                  ),
                  Effect.flatMap(publishSnapshot),
                );
              }),
            ),
        );
        const publishUrlAuthAction = runtimeCoordinator.value.watchUrlAuthAction(
          instanceId,
          (action) =>
            liveSnapshotSemaphore.withPermit(
              getSnapshot.pipe(
                Effect.flatMap((current) =>
                  publishSnapshot(
                    applyAcpRegistryUrlAuthAction(current, Option.fromNullishOr(action)),
                  ),
                ),
              ),
            ),
        );
        return Effect.all(
          [publishEnrichment, publishLiveCommands, publishLiveConfiguration, publishUrlAuthAction],
          {
            concurrency: "unbounded",
            discard: true,
          },
        );
      }),
    }).pipe(
      Effect.mapError(
        (cause) =>
          new ProviderDriverError({
            driver: DRIVER_KIND,
            instanceId,
            detail: "Failed to build the ACP Registry provider snapshot.",
            cause,
          }),
      ),
    );

    const modelProbeSemaphore = yield* Semaphore.make(1);
    const discoverModelOptions = Effect.fn("AcpRegistryDriver.discoverModelOptions")(
      function* (model: string) {
        const before = yield* Ref.get(modelObservations);
        const now = yield* Clock.currentTimeMillis;
        const observation = before.get(model);
        if (observation && now - observation.observedAt < PROBE_SUCCESS_TTL_MS) return;
        const provider = yield* snapshot.getSnapshot;
        if (
          !provider.enabled ||
          !provider.installed ||
          provider.auth.status === "unauthenticated" ||
          (provider.nativeSessions?.canDiscoverModelOptions ??
            provider.nativeSessions?.canDelete) === false ||
          !provider.models.some((candidate) => candidate.slug === model && !candidate.isCustom)
        )
          return;
        if (now < unsupportedDiscoveryUntil || now < (failedModelDiscovery.get(model) ?? 0)) return;
        const generation = yield* Ref.get(modelDiscoveryGeneration);
        const probe = probeConfiguration({ ...probeInput, model }).pipe(Effect.result);
        const result = Option.isSome(runtimeCoordinator)
          ? yield* runtimeCoordinator.value.runBackgroundProbe(probeCoordinationKey, probe)
          : Option.some(yield* probe);
        if (Option.isNone(result)) return;
        yield* liveSnapshotSemaphore.withPermit(
          Effect.gen(function* () {
            if ((yield* Ref.get(modelDiscoveryGeneration)) !== generation) return;
            const current = yield* Ref.get(modelObservations);
            if (current.get(model) !== before.get(model)) return;
            const observed = Result.isSuccess(result.value)
              ? result.value.success.modelConfiguration
              : undefined;
            if (observed?.currentModelId !== model) {
              const nextRetry = (yield* Clock.currentTimeMillis) + MODEL_DISCOVERY_RETRY_MS;
              if (
                Result.isFailure(result.value) &&
                result.value.failure.reason === "session_delete_unsupported"
              ) {
                unsupportedDiscoveryUntil = nextRetry;
              } else {
                failedModelDiscovery.set(model, nextRetry);
              }
              return;
            }
            const latest = yield* snapshot.getSnapshot;
            if (!latest.models.some((candidate) => candidate.slug === model)) return;
            const next = new Map(current).set(model, {
              descriptors: modelOptionDescriptors(observed),
              observedAt: yield* Clock.currentTimeMillis,
            });
            yield* Ref.set(modelObservations, next);
            yield* snapshot.updateSnapshot((provider) =>
              withObservedModelOptions(provider, next, effectiveConfig.customModels, current),
            );
          }),
        );
      },
      (effect) => modelProbeSemaphore.withPermit(effect),
    );

    const provideAcpManagementServices = <A, E>(
      effect: Effect.Effect<
        A,
        E,
        | AcpRegistrySupport.AcpRegistryCatalog
        | ChildProcessSpawner.ChildProcessSpawner
        | SecureRandom.SecureRandom
      >,
    ): Effect.Effect<A, E> => {
      const provided = effect.pipe(
        Effect.provideService(AcpRegistrySupport.AcpRegistryCatalog, catalog),
        Effect.provideService(ChildProcessSpawner.ChildProcessSpawner, spawner),
        Effect.provideService(SecureRandom.SecureRandom, random),
      );
      return Option.isSome(runtimeCoordinator)
        ? provided.pipe(
            Effect.provideService(
              AcpRegistryRuntimeCoordinator.AcpRegistryRuntimeCoordinator,
              runtimeCoordinator.value,
            ),
          )
        : provided;
    };

    const clearLiveState = (
      Option.isSome(runtimeCoordinator)
        ? runtimeCoordinator.value
            .clearLiveConfiguration(instanceId)
            .pipe(Effect.andThen(runtimeCoordinator.value.clearAvailableCommands(instanceId)))
        : Effect.void
    ).pipe(Effect.andThen(clearLearnedModels));
    const controller = yield* AcpRegistryAuth.makeAcpRegistryAuth({
      instanceId,
      settings: effectiveConfig,
      cwd: host.paths.cwd,
      environment: processEnvironment,
      onChanged: (authenticated) =>
        confirmedAuthentication
          .set(authenticated)
          .pipe(
            Effect.andThen(
              liveSnapshotSemaphore.withPermit(
                (authenticated ? Effect.void : clearLiveState).pipe(
                  Effect.andThen(invalidateEnrichmentCache),
                ),
              ),
            ),
            Effect.andThen(snapshot.refresh),
            Effect.asVoid,
          ),
    }).pipe(
      Effect.provideService(AcpRegistrySupport.AcpRegistryCatalog, catalog),
      Effect.provideService(ChildProcessSpawner.ChildProcessSpawner, spawner),
      Effect.provideService(SecureRandom.SecureRandom, random),
    );
    const auth = {
      ...controller,
      invalidate: (controller.invalidate ?? Effect.void).pipe(
        Effect.andThen(confirmedAuthentication.set(false)),
        Effect.andThen(
          liveSnapshotSemaphore.withPermit(
            clearLiveState.pipe(Effect.andThen(invalidateEnrichmentCache)),
          ),
        ),
        Effect.andThen(snapshot.refresh),
        Effect.asVoid,
      ),
    };

    return {
      instanceId,
      driverKind: DRIVER_KIND,
      continuationIdentity,
      displayName,
      accentColor,
      enabled,
      auth,
      snapshot: {
        ...snapshot,
        refresh: snapshot.refresh.pipe(Effect.tap(() => controller.refreshMethods ?? Effect.void)),
      },
      discoverModelOptions,
      invalidateCaches: liveSnapshotSemaphore.withPermit(
        (Option.isSome(runtimeCoordinator)
          ? runtimeCoordinator.value.clearLiveConfiguration(instanceId)
          : Effect.void
        ).pipe(Effect.andThen(resetModelDiscovery), Effect.andThen(invalidateEnrichmentCache)),
      ),
      orchestrationAdapter,
      textGeneration: makeUnsupportedTextGeneration(),
      acpSessionManagement: {
        listSessions: ({ cwd, cursor }) =>
          provideAcpManagementServices(
            listAcpRegistrySessions({
              instanceId,
              settings: effectiveConfig,
              cwd,
              environment: processEnvironment,
              ...(cursor === undefined ? {} : { cursor }),
            }),
          ),
        deleteSession: ({ cwd, sessionId }) =>
          provideAcpManagementServices(
            deleteAcpRegistrySession({
              instanceId,
              settings: effectiveConfig,
              cwd,
              environment: processEnvironment,
              sessionId,
            }),
          ),
        listProviders: (cwd) =>
          provideAcpManagementServices(
            listAcpRegistryProviders({
              instanceId,
              settings: effectiveConfig,
              cwd,
              environment: processEnvironment,
            }),
          ),
        setProvider: ({ cwd, providerId, apiType, baseUrl, headers }) =>
          provideAcpManagementServices(
            setAcpRegistryProvider({
              instanceId,
              settings: effectiveConfig,
              cwd,
              environment: processEnvironment,
              providerId,
              apiType,
              baseUrl,
              ...(headers === undefined ? {} : { headers }),
            }),
          ).pipe(
            Effect.tap(() =>
              liveSnapshotSemaphore.withPermit(
                clearLiveState.pipe(Effect.andThen(invalidateEnrichmentCache)),
              ),
            ),
          ),
        disableProvider: ({ cwd, providerId }) =>
          provideAcpManagementServices(
            disableAcpRegistryProvider({
              instanceId,
              settings: effectiveConfig,
              cwd,
              environment: processEnvironment,
              providerId,
            }),
          ).pipe(
            Effect.tap(() =>
              liveSnapshotSemaphore.withPermit(
                clearLiveState.pipe(Effect.andThen(invalidateEnrichmentCache)),
              ),
            ),
          ),
        logout: (cwd) => {
          const logout = logoutAcpRegistry({
            instanceId,
            settings: effectiveConfig,
            cwd,
            environment: processEnvironment,
          }).pipe(
            Effect.provideService(AcpRegistrySupport.AcpRegistryCatalog, catalog),
            Effect.provideService(ChildProcessSpawner.ChildProcessSpawner, spawner),
            Effect.provideService(SecureRandom.SecureRandom, random),
            Effect.tap(() => confirmedAuthentication.set(false)),
            Effect.tap(() =>
              liveSnapshotSemaphore.withPermit(
                clearLiveState.pipe(Effect.andThen(invalidateEnrichmentCache)),
              ),
            ),
          );
          return Option.isSome(runtimeCoordinator)
            ? logout.pipe(
                Effect.provideService(
                  AcpRegistryRuntimeCoordinator.AcpRegistryRuntimeCoordinator,
                  runtimeCoordinator.value,
                ),
              )
            : logout;
        },
      },
    } satisfies ProviderInstance;
  }),
};

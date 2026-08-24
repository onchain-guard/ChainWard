// Ambient declarations for `@elizaos/plugin-sql@1.7.2`.
//
// The package ships no usable types for its node entry. The chain dangles: `dist/index.d.ts`
// re-exports `./node/index`, `dist/node/index.d.ts` re-exports `./index.node`, and
// `dist/node/index.node.d.ts` does not exist — only the `.js` does. So every named import
// resolves to nothing no matter which entry or module-resolution mode is used.
//
// Declared here rather than reached for with `any`, because the alternative is losing type
// checking on the database wiring this example exists to demonstrate. Only the members the
// example actually uses are declared; this is not an attempt at a full typing.
//
// Delete this file when upstream ships the declaration.

declare module "@elizaos/plugin-sql" {
  import type { IDatabaseAdapter, Plugin, UUID } from "@elizaos/core";

  /** The plugin object registered with the runtime. */
  const sqlPlugin: Plugin;
  export default sqlPlugin;

  export interface DatabaseAdapterOptions {
    /** directory pglite writes to; omit for the in-memory variant */
    dataDir?: string;
    /** postgres connection string, when not using pglite */
    postgresUrl?: string;
  }

  /** Opaque to us — it is handed straight back to the migration service. */
  export type DrizzleDatabase = unknown;

  /** The real object implements the runtime's full adapter interface; the two members below
   *  are the ones this example calls directly. */
  export interface SqlDatabaseAdapter extends IDatabaseAdapter {
    getDatabase(): DrizzleDatabase;
  }

  export function createDatabaseAdapter(
    options: DatabaseAdapterOptions,
    agentId: UUID,
  ): SqlDatabaseAdapter;

  /**
   * Creates the tables the runtime expects. The `elizaos` CLI runs this before
   * `initialize()`; a programmatic boot must do it too, or the runtime dies on
   * `relation "agents" does not exist`.
   */
  export class DatabaseMigrationService {
    initializeWithDatabase(db: DrizzleDatabase): Promise<void>;
    discoverAndRegisterPluginSchemas(plugins: Plugin[]): void;
    runAllPluginMigrations(): Promise<void>;
  }
}

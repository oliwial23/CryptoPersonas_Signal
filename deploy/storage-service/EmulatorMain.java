/*
 * Standalone launcher for a LOCAL Cloud Bigtable emulator for the personas
 * storage-service deploy — no gcloud / cbt / Docker / Python required.
 *
 * Uses the emulator bundled in google-cloud-bigtable-emulator (the same one the
 * storage-service's own tests use via BigtableEmulatorExtension). It:
 *   1. starts the bundled emulator on a free port,
 *   2. creates the four tables the storage-service expects, each with the exact
 *      column family its code uses (GroupsTable.FAMILY="g", GroupLogTable="l",
 *      StorageItemsTable="c", StorageManifestsTable="m"),
 *   3. writes "127.0.0.1:<port>" to the file named by argv[0] (boot.sh reads it
 *      into BIGTABLE_EMULATOR_HOST),
 *   4. blocks so the emulator stays alive until killed.
 *
 * Compiled + run by bigtable.sh against the storage-service's own Maven classpath
 * (default package, so `java -cp ... EmulatorMain`).
 */

import com.google.api.gax.rpc.AlreadyExistsException;
import com.google.cloud.bigtable.admin.v2.BigtableTableAdminClient;
import com.google.cloud.bigtable.admin.v2.BigtableTableAdminSettings;
import com.google.cloud.bigtable.admin.v2.models.CreateTableRequest;
import com.google.cloud.bigtable.emulator.v2.Emulator;

import java.nio.file.Files;
import java.nio.file.Path;

public final class EmulatorMain {

  private static final String PROJECT = "personas";
  private static final String INSTANCE = "personas";

  // { table id, column family } — must match the storage-service's config table
  // ids (config.yml.template) and the FAMILY constants in its Table classes.
  private static final String[][] TABLES = {
      {"groups", "g"},
      {"group-logs", "l"},
      {"contacts", "c"},
      {"contact-manifests", "m"},
  };

  public static void main(final String[] args) throws Exception {
    final Emulator emulator = Emulator.createBundled();
    emulator.start();
    final int port = emulator.getPort();
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      try {
        emulator.stop();
      } catch (final Exception ignored) {
        // best effort
      }
    }));

    final BigtableTableAdminSettings adminSettings =
        BigtableTableAdminSettings.newBuilderForEmulator(port)
            .setProjectId(PROJECT)
            .setInstanceId(INSTANCE)
            .build();

    try (BigtableTableAdminClient admin = BigtableTableAdminClient.create(adminSettings)) {
      for (final String[] t : TABLES) {
        final String table = t[0];
        final String family = t[1];
        try {
          admin.createTable(CreateTableRequest.of(table).addFamily(family));
          System.out.println("created table " + table + " (family " + family + ")");
        } catch (final AlreadyExistsException e) {
          System.out.println("table " + table + " already exists");
        }
      }
    }

    final String hostPort = "127.0.0.1:" + port;
    if (args.length > 0) {
      Files.writeString(Path.of(args[0]), hostPort);
    }
    System.out.println("BIGTABLE_EMULATOR_HOST=" + hostPort);
    System.out.println("bigtable emulator ready; Ctrl-C (or bigtable.sh down) to stop.");

    // Keep the JVM (and thus the emulator subprocess) alive.
    Thread.currentThread().join();
  }
}

// startServer.js
// Pure boot-strapper: spins up cluster or single worker.
// Exports a function you call once FROM app.js.

const http     = require('http');
const os       = require('os');
const cluster  = require('cluster');

/**
 * startServer({ app, logger, redisClient, admin })
 * ------------------------------------------------
 * • Keeps the exact RAM/CPU logic from your monolith.
 * • Performs graceful shutdown identical to original code.
 */
module.exports = function startServer ({
  app,
  logger,
  redisClient,
  admin
}) {

  /* ─────────── START THE SERVER (memory-aware) ─────────── */
  const PORT = process.env.PORT || 3000;

  /* Compute a safe worker count (unchanged maths) */
  const MB                  = 1024 * 1024;
  const memLimitMiB         = parseInt(process.env.RENDER_MEMORY_LIMIT_MIB || 512, 10);
  const approxPerWorkerMiB  = 70;
  const maxByRam            = Math.floor((memLimitMiB * 0.75) / approxPerWorkerMiB) || 1;
  const cpuCount            = os.cpus().length;

  const CPUS = Math.max(
    1,
    parseInt(process.env.WEB_CONCURRENCY || Math.min(cpuCount, maxByRam), 10)
  );

  /* ────────── MODE A – cluster (≥2 workers) ────────── */
  if (CPUS > 1 && cluster.isPrimary) {
    logger.info(`🛡  Master ${process.pid} starting ${CPUS} worker(s)…`);

    for (let i = 0; i < CPUS; i++) cluster.fork();

    /* simple respawn – keeps the dyno alive */
    cluster.on('exit', (worker, code, signal) => {
      logger.warn(`⚠️  Worker ${worker.process.pid} exited (${signal || code}); restarting…`);
      setTimeout(() => cluster.fork(), 2000);
    });

  /* ────────── MODE B – single-process fallback ────────── */
  } else {
    if (cluster.isPrimary)
      logger.info('ℹ️  Running in single-process mode (memory-safe)');

    const server = http.createServer(app).listen(PORT, () => {
      logger.info(`✅  PID ${process.pid} listening on :${PORT}`);
    });

    /* graceful shutdown with hard-kill safeguard */
    let killTimer = null;
    const graceful = async (reason) => {
      if (killTimer) return;                     // duplicate guard
      logger.warn(`⏳  PID ${process.pid} shutting down – ${reason}`);

      killTimer = setTimeout(() => {
        logger.error('❌  Force-killing stuck process (grace period elapsed)');
        process.exit(1);
      }, 30_000).unref();

      server.close(() => logger.info('HTTP closed'));

      await Promise.allSettled([
        redisClient.quit().catch(() => {}),
        admin.app().delete().catch(() => {})
      ]);

      clearTimeout(killTimer);
      process.exit(0);
    };

    process
      .on('SIGTERM', () => graceful('SIGTERM'))
      .on('SIGINT',  () => graceful('SIGINT'))
      .on('uncaughtException', (err) => {
        console.error('❌  Uncaught exception:', err);
        graceful('uncaughtException');
      });
  }
};

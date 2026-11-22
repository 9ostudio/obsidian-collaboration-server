import esbuild from 'esbuild'
import path from 'node:path'

const pluginDir = path.resolve(process.env.PLUGIN_DIR || 'plugin')

await esbuild.build({
  entryPoints: ['test/e2e.test.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  outfile: 'test/dist/e2e.test.mjs',
  alias: { '@plugin': path.join(pluginDir, 'src') },
  nodePaths: [path.join(pluginDir, 'node_modules')],
  logLevel: 'warning'
})

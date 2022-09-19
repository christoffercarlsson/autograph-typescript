import { globby } from 'globby'
import { exit } from 'process'
import { build } from 'stedy/build'

const run = async () => {
  const entryPoints = await globby('src/**/*.js', {
    onlyFiles: true
  })
  await build(entryPoints, {
    clean: true
  })
}

run().catch((error) => {
  console.error(error)
  exit(1)
})

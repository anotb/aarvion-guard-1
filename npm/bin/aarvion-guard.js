#!/usr/bin/env node
'use strict'

// Thin launcher for `npx @aarvion/guard`: downloads the platform binary from
// GitHub Releases into a cache on first use, then execs it with the given args.
const fs = require('fs')
const os = require('os')
const path = require('path')
const https = require('https')
const { spawnSync } = require('child_process')

const REPO = 'aarvion-ai/aarvion-guard'
const VERSION = 'v' + require('../package.json').version

function assetName() {
  const platform = os.platform()
  const arch = { x64: 'amd64', arm64: 'arm64' }[os.arch()]
  const osName = { darwin: 'darwin', linux: 'linux' }[platform]
  if (!osName || !arch) {
    console.error(`unsupported platform: ${platform}/${os.arch()}`)
    process.exit(1)
  }
  return `aarvion-guard_${osName}_${arch}`
}

function cachePath(name) {
  const dir = path.join(os.homedir(), '.aarvion', 'cache', VERSION)
  fs.mkdirSync(dir, { recursive: true })
  return path.join(dir, name)
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest, { mode: 0o755 })
    const get = (u) =>
      https.get(u, (res) => {
        if (res.statusCode === 302 || res.statusCode === 301) {
          return get(res.headers.location)
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`download ${u} failed: ${res.statusCode}`))
        }
        res.pipe(file)
        file.on('finish', () => file.close(resolve))
      })
    get(url).on('error', (e) => {
      fs.rmSync(dest, { force: true })
      reject(e)
    })
  })
}

async function main() {
  const name = assetName()
  const bin = cachePath(name)
  if (!fs.existsSync(bin)) {
    const url = `https://github.com/${REPO}/releases/download/${VERSION}/${name}`
    process.stderr.write(`downloading aarvion-guard ${VERSION}...\n`)
    await download(url, bin)
    fs.chmodSync(bin, 0o755)
  }
  const r = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' })
  process.exit(r.status === null ? 1 : r.status)
}

main().catch((e) => {
  console.error(e.message)
  process.exit(1)
})

#!/usr/bin/env node
'use strict'

// Thin launcher for `npx @aarvionai/guard`: downloads the platform binary from
// GitHub Releases into a cache on first use, then execs it with the given args.
const fs = require('fs')
const os = require('os')
const path = require('path')
const https = require('https')
const { spawnSync } = require('child_process')

const REPO = 'aarvion-ai/aarvion-guard'
// The release tag the binaries live under, decoupled from the npm package
// version so shim-only fixes don't require rebuilding binaries.
const BINARY_TAG = 'v0.1.0'

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
  const dir = path.join(os.homedir(), '.aarvion', 'cache', BINARY_TAG)
  fs.mkdirSync(dir, { recursive: true })
  return path.join(dir, name)
}

// Never leaves a partial/empty file behind: the write stream is only opened
// after a 200, and any failure unlinks the destination so a poisoned cache
// can't block future runs.
function download(url, dest) {
  return new Promise((resolve, reject) => {
    const fail = (e) => {
      fs.rmSync(dest, { force: true })
      reject(e)
    }
    const get = (u) =>
      https
        .get(u, (res) => {
          const { statusCode, headers } = res
          if ([301, 302, 303, 307, 308].includes(statusCode) && headers.location) {
            res.resume()
            return get(headers.location)
          }
          if (statusCode !== 200) {
            res.resume()
            return fail(new Error(`download ${u} failed: ${statusCode}`))
          }
          const file = fs.createWriteStream(dest, { mode: 0o755 })
          file.on('error', fail)
          res.on('error', fail)
          res.pipe(file)
          file.on('finish', () => file.close(() => resolve()))
        })
        .on('error', fail)
    get(url)
  })
}

async function main() {
  const name = assetName()
  const bin = cachePath(name)
  if (!fs.existsSync(bin) || fs.statSync(bin).size === 0) {
    const url = `https://github.com/${REPO}/releases/download/${BINARY_TAG}/${name}`
    process.stderr.write(`downloading aarvion-guard ${BINARY_TAG}...\n`)
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

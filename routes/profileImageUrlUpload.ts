/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'
import net from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIp (ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number)
    const [a, b, c, d] = parts
    if (a === 10) return true // 10.0.0.0/8
    if (a === 127) return true // 127.0.0.0/8
    if (a === 169 && b === 254) return true // 169.254.0.0/16
    if (a === 172 && b >= 16 && b <= 31) return true // 172.16.0.0/12
    if (a === 192 && b === 168) return true // 192.168.0.0/16
    if (a === 0) return true // 0.0.0.0/8
    if (a >= 224) return true // Multicast / Reserved
    return false
  } else if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase()
    if (normalized === '::1' || normalized === '::') return true
    
    // Link-local: fe80::/10 -> starts with fe8, fe9, fea, feb
    if (/^fe[89ab]/i.test(normalized)) return true
    
    // Unique Local: fc00::/7 -> starts with fc or fd
    if (/^f[cd]/i.test(normalized)) return true
    
    // Multicast: ff00::/8 -> starts with ff
    if (/^ff/i.test(normalized)) return true
    
    // Check if the IP starts with any representation of 0000:0000:0000:0000:0000:0000:0000
    if (normalized.replace(/:/g, '') === '00000000000000000000000000000001') return true
    if (normalized.replace(/:/g, '') === '00000000000000000000000000000000') return true
    
    // IPv4-mapped IPv6 addresses, e.g. ::ffff:127.0.0.1
    if (normalized.startsWith('::ffff:')) {
      const ipv4Part = ip.slice(7)
      if (net.isIPv4(ipv4Part)) {
        return isPrivateIp(ipv4Part)
      }
    }
    
    return false
  }
  return true // If not valid IPv4 or IPv6, treat as unsafe/private
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  try {
    const parsed = new URL(urlString)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false
    }
    
    const hostname = parsed.hostname.toLowerCase()
    
    // Check if hostname is an IP directly to avoid DNS lookup for simple cases
    if (net.isIP(hostname)) {
      return !isPrivateIp(hostname)
    }

    // Resolve hostname to IP address
    const result = await dns.promises.lookup(hostname, { all: true })
    const ipList: string[] = []
    if (Array.isArray(result)) {
      for (const item of result) {
        if (item.address) ipList.push(item.address)
      }
    } else if (result && typeof result === 'object' && 'address' in result) {
      ipList.push((result as any).address)
    }
    
    for (const ip of ipList) {
      if (isPrivateIp(ip)) {
        return false
      }
    }
    
    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!await isSafeUrl(url)) {
            throw new Error('SSRF protection: Invalid or private URL')
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}

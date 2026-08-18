/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'
import { isIP } from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIp (ip: string): boolean {
  let normalizedIp = ip.trim().toLowerCase()

  // Handle IPv4-mapped IPv6
  if (normalizedIp.startsWith('::ffff:')) {
    const ipv4Part = normalizedIp.substring(7)
    if (isIP(ipv4Part) === 4) {
      normalizedIp = ipv4Part
    } else {
      return true // Treat unparseable/hex IPv4-mapped as unsafe
    }
  }

  const ipVersion = isIP(normalizedIp)
  if (ipVersion === 4) {
    const parts = normalizedIp.split('.').map(Number)
    if (parts.length !== 4 || parts.some(isNaN)) {
      return true
    }
    // Loopback: 127.0.0.0/8
    if (parts[0] === 127) return true
    // Private RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if (parts[0] === 10) return true
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
    if (parts[0] === 192 && parts[1] === 168) return true
    // Link-local: 169.254.0.0/16
    if (parts[0] === 169 && parts[1] === 254) return true
    // Shared Address Space: 100.64.0.0/10
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true
    // Local / current network: 0.0.0.0/8
    if (parts[0] === 0) return true
    // Multicast: 224.0.0.0/4
    if (parts[0] >= 224) return true

    return false
  }

  if (ipVersion === 6) {
    // Loopback: ::1
    if (normalizedIp === '::1' || normalizedIp === '0:0:0:0:0:0:0:1') return true
    // Unspecified: ::
    if (normalizedIp === '::' || normalizedIp === '0:0:0:0:0:0:0:0') return true
    // Unique local address: fc00::/7
    if (normalizedIp.startsWith('fc') || normalizedIp.startsWith('fd')) return true
    // Link-local unicast: fe80::/10
    if (normalizedIp.startsWith('fe8') || normalizedIp.startsWith('fe9') || normalizedIp.startsWith('fea') || normalizedIp.startsWith('feb')) return true
    // Multicast: ff00::/8
    if (normalizedIp.startsWith('ff')) return true

    return false
  }

  return true // Block anything else that is not a valid IP version
}

async function isSafeUrl (urlStr: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlStr)
    // Only allow http: or https:
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }

    const hostname = parsedUrl.hostname.trim().toLowerCase()
    if (!hostname) {
      return false
    }

    // Block obvious local names
    if (hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.localhost')) {
      return false
    }

    // If it's directly an IP address
    if (isIP(hostname)) {
      if (isPrivateIp(hostname)) {
        return false
      }
    }

    // Resolve DNS to check the underlying IPs
    try {
      const addresses = await dns.promises.lookup(hostname, { all: true })
      for (const addr of addresses) {
        if (isPrivateIp(addr.address)) {
          return false
        }
      }
    } catch {
      // If we cannot resolve it, block it to be safe
      return false
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
          if (!(await isSafeUrl(url))) {
            res.status(400)
            next(new Error('Blocked unsafe URL'))
            return
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

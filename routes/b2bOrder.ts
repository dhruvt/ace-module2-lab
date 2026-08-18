/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

function isCodeSafe (code: string): boolean {
  const lower = code.toLowerCase()
  const forbidden = [
    'constructor', 'prototype', '__proto__', 'global', 'process', 'require',
    'exec', 'spawn', 'function', 'import', 'eval', 'fs', 'child_process', 'os',
    'path', 'reflect', 'proxy', 'symbol', 'mainmodule', 'currenttarget', 'view',
    'window', 'document', 'this', 'globalthis', 'self', 'top', 'parent', 'frames',
    'arguments', 'object', 'module', 'exports', 'settimeout', 'setinterval',
    'setimmediate', 'cleartimeout', 'clearinterval', 'clearimmediate', 'array',
    'string', 'number', 'boolean', 'regexp', 'error'
  ]
  for (const word of forbidden) {
    if (lower.includes(word)) {
      return false
    }
  }
  // Block any backslash to be completely safe against escape tricks
  if (code.includes('\\')) {
    return false
  }
  // Block template literals (backticks)
  if (code.includes('`')) {
    return false
  }
  // Block computed property access via bracket notation
  if (/([a-zA-Z0-9_$)"'\`\]}{])\s*\[/.test(code)) {
    return false
  }
  return true
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      if (!isCodeSafe(orderLinesData)) {
        next(new Error('Blocked potential malicious code execution'))
        return
      }
      try {
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}

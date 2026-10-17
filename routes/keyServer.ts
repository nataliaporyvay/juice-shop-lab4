/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const ALLOWED_KEY_FILES: Record<string, string> = {
  'jwt.pub': path.resolve('encryptionkeys/jwt.pub')
}

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/')) {
      res.status(403)
      return next(new Error('File names cannot contain forward slashes!'))
    }

    const allowedPath = Object.prototype.hasOwnProperty.call(ALLOWED_KEY_FILES, file)
      ? ALLOWED_KEY_FILES[file]
      : undefined

    if (allowedPath === undefined) {
      res.status(403)
      return next(new Error('Access to this key file is forbidden!'))
    }

    res.sendFile(allowedPath, (err) => {
      if (err != null) {
        next(err)
      }
    })
  }
}

/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import frisby = require('frisby')
import { expect } from '@jest/globals'
import config from 'config'
import { initialize, bot } from '../../routes/chatbot'
import fs from 'fs/promises'
import * as utils from '../../lib/utils'

// Load environment variables
import dotenv from 'dotenv'
dotenv.config()

const URL = 'http://localhost:3000'
const REST_URL = `${URL}/rest/`
const API_URL = `${URL}/api/`
let trainingData: { data: any[] }

async function login({ email, password }: { email: string, password: string }) {
  // @ts-expect-error FIXME promise return handling broken
  const loginRes = await frisby
    .post(REST_URL + '/user/login', {
      email,
      password
    }).catch((res: any) => {
      if (res.json?.type && res.json.status === 'totp_token_required') {
        return res
      }
      throw new Error(`Failed to login '${email}'`)
    })

  return loginRes.json.authentication
}

describe('/chatbot', () => {
  beforeAll(async () => {
    await initialize()
    trainingData = JSON.parse(
      await fs.readFile(`data/chatbot/${utils.extractFilename(config.get('application.chatBot.trainingData'))}`, { encoding: 'utf8' })
    )
  })

  describe('/status', () => {
    it('GET bot training state', () => {
      return frisby.get(REST_URL + 'chatbot/status')
        .expect('status', 200)
        .expect('json', 'status', true)
    })

    it('GET bot state for anonymous users contains log in request', () => {
      return frisby.get(REST_URL + 'chatbot/status')
        .expect('status', 200)
        .expect('json', 'body', /Sign in to talk/)
    })

    it('GET bot state for authenticated users contains request for username', async () => {
      const { token } = await login({
        email: process.env.CHATBOT_TEST_EMAIL || `J12934@${config.get<string>('application.domain')}`,
        password: process.env.CHATBOT_TEST_PASSWORD || 'secure_fallback_password'
      })

      await frisby.setup({
        request: {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        }
      }, true).get(REST_URL + 'chatbot/status')
        .expect('status', 200)
        .expect('json', 'body', /What shall I call you?/)
        .promise()
    })
  })

  describe('/respond', () => {
    it('Asks for username if not defined', async () => {
      const { token } = await login({
        email: process.env.CHATBOT_TEST_EMAIL || `J12934@${config.get<string>('application.domain')}`,
        password: process.env.CHATBOT_TEST_PASSWORD || 'secure_fallback_password'
      })

      const testCommand = trainingData.data[0].utterances[0]

      await frisby.setup({
        request: {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        }
      }, true)
        .post(REST_URL + 'chatbot/respond', {
          body: {
            action: 'query',
            query: testCommand
          }
        })
        .expect('status', 200)
        .expect('json', 'action', 'namequery')
        .expect('json', 'body', 'I\'m sorry I didn\'t get your name. What shall I call you?')
        .promise()
    })

    it('Returns greeting if username is defined', async () => {
      if (bot == null) {
        throw new Error('Bot not initialized')
      }
      const { token } = await login({
        email: process.env.CHATBOT_ADMIN_EMAIL || 'admin@example.com',
        password: process.env.CHATBOT_ADMIN_PASSWORD || 'secure_admin_password'
      })

      bot.addUser('1337', 'adminUser')
      const testCommand = trainingData.data[0].utterances[0]

      await frisby.setup({
        request: {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        }
      }, true)
        .post(REST_URL + 'chatbot/respond', {
          body: {
            action: 'query',
            query: testCommand
          }
        })
        .expect('status', 200)
        .expect('json', 'action', 'response')
        .expect('json', 'body', bot.greet('1337'))
        .promise()
    })
  })
})

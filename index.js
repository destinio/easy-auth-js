import sqlite3 from 'sqlite3'
import bcrypt from 'bcrypt'
import input from '@inquirer/input'

const db = new sqlite3.Database('./users.db')

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      password TEXT
    )`)
})

async function getUserInput() {
  const name = await input({ message: 'Enter your name' })

  if (!name) {
    throw new Error('Name is required')
  }

  const password = await input({
    message: 'Enter your password',
    type: 'password',
  })

  if (!password) {
    throw new Error('Password is required')
  }

  return { name, password }
}

async function signUp() {
  const { name, password } = await getUserInput()

  if (!name || !password) {
    console.error('Name and password are required')
    return
  }

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error(err)
      return
    }

    db.run(
      'INSERT INTO users (id, name, password) VALUES (?, ?, ?)',
      [crypto.randomUUID(), name, hash],
      err => {
        if (err) {
          console.error(err)
          return
        }

        console.log('User saved')
      },
    )
  })
}

async function signIn() {
  let valid = false

  try {
    const { name, password } = await getUserInput()

    if (!name || !password) {
      console.error('Name and password are required')
      return
    }

    const user = await new Promise((resolve, reject) => {
      db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, row) => {
        if (err) {
          reject(err)
          return
        }

        resolve(row)
      })
    })

    if (user) {
      const result = await bcrypt.compare(password, user.password)

      if (result) {
        console.log('User authenticated')
        valid = true
      }
    }
  } catch (error) {
    console.log(error.message)
  }

  return valid
}

async function main() {
  const command = process.argv[2]

  switch (command) {
    case 'signin':
      const valid = await signIn()

      if (valid) {
        console.log('Welcome!')
        return
      }

      console.log('Invalid credentials')
      break
    case 'signup':
      signUp()
      break
    default:
      console.error('Invalid command')
  }
}

main()

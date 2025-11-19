const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Подключение к PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Функция для создания таблиц
async function createTables() {
  try {
    console.log('🔄 Проверка и создание таблиц...');

    // Таблица пользователей
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Таблица временных регистраций
    await pool.query(`
      CREATE TABLE IF NOT EXISTS temp_registrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        verification_code VARCHAR(6) NOT NULL,
        code_expires TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Таблица чатов
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chats (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Таблица сообщений
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
        role VARCHAR(20) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Создание индексов
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_chats_user_id ON chats(user_id)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_temp_registrations_email ON temp_registrations(email)
    `);

    console.log('✅ Все таблицы созданы/проверены успешно!');
    
  } catch (error) {
    console.error('❌ Ошибка при создании таблиц:', error);
  }
}

// Конфигурация email (ИСПРАВЛЕННАЯ СТРОКА)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Middleware для проверки JWT токена
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Токен доступа отсутствует' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Неверный токен' });
    }
    req.user = user;
    next();
  });
};

// Генерация случайного кода
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// 1. Отправка кода подтверждения
app.post('/auth/send-code', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Валидация
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Все поля обязательны' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Пароль должен содержать минимум 6 символов' });
    }

    // Проверяем, существует ли пользователь
    const userExists = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
    }

    // Генерируем код подтверждения
    const verificationCode = generateVerificationCode();
    const codeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 минут

    // Сохраняем временные данные
    await pool.query(
      `INSERT INTO temp_registrations (name, email, password, verification_code, code_expires)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (email) 
       DO UPDATE SET name = $1, password = $3, verification_code = $4, code_expires = $5, created_at = NOW()`,
      [name, email, await bcrypt.hash(password, 10), verificationCode, codeExpires]
    );

    // Отправляем email с кодом (в демо-режиме просто возвращаем код)
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Код подтверждения для Gemini Chat',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #4a1e6d;">Добро пожаловать в Gemini Chat!</h2>
            <p>Ваш код подтверждения: <strong style="font-size: 24px; color: #4a1e6d;">${verificationCode}</strong></p>
            <p>Код действителен в течение 10 минут.</p>
            <p>Если вы не регистрировались в Gemini Chat, просто проигнорируйте это письмо.</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">С уважением,<br>Команда Gemini Chat</p>
          </div>
        `
      };

      await transporter.sendMail(mailOptions);
      res.json({ message: 'Код подтверждения отправлен на вашу почту' });
    } else {
      // Демо-режим - возвращаем код в ответе
      res.json({ 
        message: 'Код подтверждения (демо-режим)',
        demo_code: verificationCode 
      });
    }

  } catch (error) {
    console.error('Ошибка отправки кода:', error);
    res.status(500).json({ error: 'Ошибка сервера при отправке кода' });
  }
});

// 2. Подтверждение кода и регистрация
app.post('/auth/verify', async (req, res) => {
  try {
    const { email, code } = req.body;

    // В демо-режиме пропускаем проверку кода
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      const tempUser = await pool.query(
        'SELECT * FROM temp_registrations WHERE email = $1',
        [email]
      );

      if (tempUser.rows.length === 0) {
        return res.status(400).json({ error: 'Пользователь не найден' });
      }

      const userData = tempUser.rows[0];

      // Создаем пользователя
      const newUser = await pool.query(
        `INSERT INTO users (name, email, password) 
         VALUES ($1, $2, $3) 
         RETURNING id, name, email, created_at`,
        [userData.name, userData.email, userData.password]
      );

      // Удаляем временную запись
      await pool.query('DELETE FROM temp_registrations WHERE email = $1', [email]);

      // Генерируем JWT токен
      const token = jwt.sign(
        { userId: newUser.rows[0].id, email: newUser.rows[0].email },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '30d' }
      );

      return res.json({
        token,
        user: {
          id: newUser.rows[0].id,
          name: newUser.rows[0].name,
          email: newUser.rows[0].email
        }
      });
    }

    // Продакшен-режим с проверкой кода
    const tempUser = await pool.query(
      `SELECT * FROM temp_registrations 
       WHERE email = $1 AND verification_code = $2 AND code_expires > NOW()`,
      [email, code]
    );

    if (tempUser.rows.length === 0) {
      return res.status(400).json({ error: 'Неверный код или время его действия истекло' });
    }

    const userData = tempUser.rows[0];

    // Создаем пользователя
    const newUser = await pool.query(
      `INSERT INTO users (name, email, password) 
       VALUES ($1, $2, $3) 
       RETURNING id, name, email, created_at`,
      [userData.name, userData.email, userData.password]
    );

    // Удаляем временную запись
    await pool.query('DELETE FROM temp_registrations WHERE email = $1', [email]);

    // Генерируем JWT токен
    const token = jwt.sign(
      { userId: newUser.rows[0].id, email: newUser.rows[0].email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: {
        id: newUser.rows[0].id,
        name: newUser.rows[0].name,
        email: newUser.rows[0].email
      }
    });
  } catch (error) {
    console.error('Ошибка верификации:', error);
    res.status(500).json({ error: 'Ошибка сервера при верификации' });
  }
});

// 3. Получение чатов пользователя
app.get('/chats', authenticateToken, async (req, res) => {
  try {
    const chats = await pool.query(
      `SELECT id, title, created_at, updated_at 
       FROM chats 
       WHERE user_id = $1 
       ORDER BY updated_at DESC`,
      [req.user.userId]
    );

    res.json(chats.rows);
  } catch (error) {
    console.error('Ошибка получения чатов:', error);
    res.status(500).json({ error: 'Ошибка сервера при получении чатов' });
  }
});

// 4. Создание нового чата
app.post('/chats', authenticateToken, async (req, res) => {
  try {
    const { title = 'Новый чат' } = req.body;

    const newChat = await pool.query(
      `INSERT INTO chats (user_id, title) 
       VALUES ($1, $2) 
       RETURNING id, title, created_at, updated_at`,
      [req.user.userId, title]
    );

    res.json(newChat.rows[0]);
  } catch (error) {
    console.error('Ошибка создания чата:', error);
    res.status(500).json({ error: 'Ошибка сервера при создании чата' });
  }
});

// 5. Сохранение сообщений чата
app.post('/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { messages } = req.body;

    // Проверяем, принадлежит ли чат пользователю
    const chat = await pool.query(
      'SELECT id FROM chats WHERE id = $1 AND user_id = $2',
      [chatId, req.user.userId]
    );

    if (chat.rows.length === 0) {
      return res.status(404).json({ error: 'Чат не найден' });
    }

    // Удаляем старые сообщения и сохраняем новые
    await pool.query('DELETE FROM messages WHERE chat_id = $1', [chatId]);

    for (const message of messages) {
      await pool.query(
        `INSERT INTO messages (chat_id, role, content) 
         VALUES ($1, $2, $3)`,
        [chatId, message.role, message.content]
      );
    }

    // Обновляем время изменения чата
    await pool.query(
      'UPDATE chats SET updated_at = NOW() WHERE id = $1',
      [chatId]
    );

    res.json({ message: 'Сообщения сохранены' });
  } catch (error) {
    console.error('Ошибка сохранения сообщений:', error);
    res.status(500).json({ error: 'Ошибка сервера при сохранении сообщений' });
  }
});

// 6. Получение сообщений чата
app.get('/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;

    const messages = await pool.query(
      `SELECT role, content, created_at 
       FROM messages 
       WHERE chat_id = $1 
       ORDER BY created_at ASC`,
      [chatId]
    );

    res.json(messages.rows);
  } catch (error) {
    console.error('Ошибка получения сообщений:', error);
    res.status(500).json({ error: 'Ошибка сервера при получении сообщений' });
  }
});

// 7. Удаление чата
app.delete('/chats/:chatId', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;

    await pool.query('DELETE FROM chats WHERE id = $1 AND user_id = $2', [
      chatId,
      req.user.userId
    ]);

    res.json({ message: 'Чат удален' });
  } catch (error) {
    console.error('Ошибка удаления чата:', error);
    res.status(500).json({ error: 'Ошибка сервера при удалении чата' });
  }
});

// Тестовый эндпоинт для проверки базы
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ 
      status: 'OK', 
      database: 'connected',
      tables_created: true 
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'ERROR', 
      database: 'disconnected',
      error: error.message 
    });
  }
});

// Запуск сервера
app.listen(PORT, async () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
  
  // Создаем таблицы при запуске
  await createTables();
  
  console.log(`✅ Сервер готов к работе!`);
  console.log(`📧 Email режим: ${process.env.EMAIL_USER ? 'ВКЛ' : 'ВЫКЛ (демо)'}`);
});

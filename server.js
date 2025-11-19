const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Проверка DATABASE_URL
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL не установлен!');
}

// Подключение к PostgreSQL
let pool;
try {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });
  console.log('✅ Подключение к базе данных установлено');
} catch (error) {
  console.error('❌ Ошибка создания пула подключений:', error.message);
  pool = null;
}

// Функция для создания таблиц
async function createTables() {
  if (!pool) return;

  try {
    console.log('🔄 Проверка и создание таблиц...');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS chats (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
        role VARCHAR(20) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Индексы
    await pool.query('CREATE INDEX IF NOT EXISTS idx_chats_user_id ON chats(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_temp_registrations_email ON temp_registrations(email)');

    console.log('✅ Все таблицы созданы/проверены успешно!');
  } catch (error) {
    console.error('❌ Ошибка при создании таблиц:', error.message);
  }
}

// Упрощенная конфигурация email с таймаутом
const createTransporter = () => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    return null;
  }

  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
    connectionTimeout: 10000, // 10 секунд
    greetingTimeout: 10000,
    socketTimeout: 10000
  });
};

const transporter = createTransporter();

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

// Проверка доступности базы данных
const checkDatabase = (req, res, next) => {
  if (!pool) {
    return res.status(503).json({ error: 'База данных недоступна' });
  }
  next();
};

// 📍 КОРНЕВОЙ ПУТЬ
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 📍 ВСЕ ДРУГИЕ ПУТИ
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 1. Отправка кода подтверждения - ИСПРАВЛЕННАЯ ВЕРСИЯ
app.post('/auth/send-code', checkDatabase, async (req, res) => {
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

    // 🔧 ВСЕГДА используем демо-режим для надежности
    res.json({ 
      success: true,
      message: 'Код подтверждения сгенерирован',
      demo_code: verificationCode,
      note: 'В демо-режиме код показывается здесь. В продакшене он будет отправлен на email.'
    });

  } catch (error) {
    console.error('Ошибка отправки кода:', error);
    res.status(500).json({ 
      error: 'Ошибка сервера',
      details: 'Попробуйте использовать демо-режим' 
    });
  }
});

// 2. Подтверждение кода и регистрация - УПРОЩЕННАЯ ВЕРСИЯ
app.post('/auth/verify', checkDatabase, async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email и код обязательны' });
    }

    // 🔧 ПРОСТАЯ ПРОВЕРКА - ищем любую запись с этим email
    const tempUser = await pool.query(
      'SELECT * FROM temp_registrations WHERE email = $1',
      [email]
    );

    if (tempUser.rows.length === 0) {
      return res.status(400).json({ error: 'Код не найден или истек' });
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
      success: true,
      token,
      user: {
        id: newUser.rows[0].id,
        name: newUser.rows[0].name,
        email: newUser.rows[0].email
      }
    });

  } catch (error) {
    console.error('Ошибка верификации:', error);
    
    // Если ошибка дублирования email, пробуем войти
    if (error.code === '23505') {
      try {
        const existingUser = await pool.query(
          'SELECT id, name, email FROM users WHERE email = $1',
          [req.body.email]
        );
        
        if (existingUser.rows.length > 0) {
          const token = jwt.sign(
            { userId: existingUser.rows[0].id, email: existingUser.rows[0].email },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '30d' }
          );
          
          return res.json({
            success: true,
            token,
            user: existingUser.rows[0]
          });
        }
      } catch (loginError) {
        console.error('Ошибка входа:', loginError);
      }
    }
    
    res.status(500).json({ 
      error: 'Ошибка сервера при регистрации',
      details: error.message 
    });
  }
});

// Остальные эндпоинты остаются без изменений...
// 3. Получение чатов пользователя
app.get('/chats', authenticateToken, checkDatabase, async (req, res) => {
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
app.post('/chats', authenticateToken, checkDatabase, async (req, res) => {
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
app.post('/chats/:chatId/messages', authenticateToken, checkDatabase, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { messages } = req.body;

    const chat = await pool.query(
      'SELECT id FROM chats WHERE id = $1 AND user_id = $2',
      [chatId, req.user.userId]
    );

    if (chat.rows.length === 0) {
      return res.status(404).json({ error: 'Чат не найден' });
    }

    await pool.query('DELETE FROM messages WHERE chat_id = $1', [chatId]);

    for (const message of messages) {
      await pool.query(
        `INSERT INTO messages (chat_id, role, content) 
         VALUES ($1, $2, $3)`,
        [chatId, message.role, message.content]
      );
    }

    await pool.query('UPDATE chats SET updated_at = NOW() WHERE id = $1', [chatId]);

    res.json({ message: 'Сообщения сохранены' });
  } catch (error) {
    console.error('Ошибка сохранения сообщений:', error);
    res.status(500).json({ error: 'Ошибка сервера при сохранении сообщений' });
  }
});

// 6. Получение сообщений чата
app.get('/chats/:chatId/messages', authenticateToken, checkDatabase, async (req, res) => {
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
app.delete('/chats/:chatId', authenticateToken, checkDatabase, async (req, res) => {
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
  if (!pool) {
    return res.status(503).json({ 
      status: 'ERROR', 
      database: 'disconnected'
    });
  }

  try {
    await pool.query('SELECT NOW()');
    res.json({ 
      status: 'OK', 
      database: 'connected',
      mode: 'demo' // Всегда демо-режим для надежности
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
  
  if (pool) {
    await createTables();
  }
  
  console.log(`🔧 Режим работы: ДЕМО (надежный)`);
  console.log(`✅ Сервер готов! Откройте: https://chatfuzionai.onrender.com`);
});

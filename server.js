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

// Подключение к PostgreSQL (ваша база на Render.com)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://username:password@host:port/database',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Конфигурация email (используем Gmail)
const transporter = nodemailer.createTransporter({
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

    // Отправляем email с кодом
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
  } catch (error) {
    console.error('Ошибка отправки кода:', error);
    res.status(500).json({ error: 'Ошибка сервера при отправке кода' });
  }
});

// 2. Подтверждение кода и регистрация
app.post('/auth/verify', async (req, res) => {
  try {
    const { email, code } = req.body;

    // Находим временную запись
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

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});
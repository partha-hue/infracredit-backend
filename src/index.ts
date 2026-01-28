import express, { Request, Response } from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { authenticate, AuthRequest } from './middlewares/auth';
import twilio from 'twilio';

const prisma = new PrismaClient();
const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' }));

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';
// Production-safe: Secrets are now read from Environment Variables
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

const twilioClient = TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN ? twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) : null;

const generateTokens = (userId: string) => {
  const accessToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
  const refreshToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
  return { accessToken, refreshToken };
};

// --- AUTH ---

app.post('/v1/auth/register', async (req: Request, res: Response) => {
  const { phone, fullName, businessName, password, email } = req.body;
  try {
    const existingPhone = await prisma.user.findUnique({ where: { phone } });
    if (existingPhone) return res.status(400).json({ error: 'Phone already registered' });

    let user;
    if (email) {
      const existingEmail = await prisma.user.findUnique({ where: { email } });
      if (existingEmail && !existingEmail.phone) {
        const hashedPassword = await bcrypt.hash(password, 12);
        user = await prisma.user.update({
          where: { id: existingEmail.id },
          data: { 
            phone, 
            fullName, 
            businessName: businessName || existingEmail.businessName, 
            passwordHash: hashedPassword,
            isMigrated: true 
          }
        });
      }
    }

    if (!user) {
      const hashedPassword = await bcrypt.hash(password, 12);
      user = await prisma.user.create({
        data: { 
          phone, 
          fullName, 
          businessName: businessName || null, 
          passwordHash: hashedPassword,
          email: email || null,
          isMigrated: false 
        }
      });
    }

    const { accessToken, refreshToken } = generateTokens(user.id);
    res.json({ accessToken, refreshToken, userId: user.id, fullName: user.fullName, businessName: user.businessName });
  } catch (error) {
    res.status(400).json({ error: 'Registration failed' });
  }
});

app.post('/v1/auth/login', async (req: Request, res: Response) => {
  const { phone, password } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { phone } });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const { accessToken, refreshToken } = generateTokens(user.id);
    res.json({ accessToken, refreshToken, userId: user.id, fullName: user.fullName, businessName: user.businessName });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/v1/auth/forgot-password', async (req: Request, res: Response) => {
  const { phone } = req.query;
  try {
    if (!twilioClient || !TWILIO_PHONE_NUMBER) {
      return res.status(500).json({ error: 'SMS Service not configured' });
    }

    const user = await prisma.user.findUnique({ where: { phone: phone as string } });
    if (!user) {
      return res.json({ success: true, message: 'If registered, an OTP will be sent.' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    await prisma.user.update({
      where: { id: user.id },
      data: { resetToken: otp }
    });

    await twilioClient.messages.create({
      body: `Your InfraCredit password reset OTP is: ${otp}`,
      from: TWILIO_PHONE_NUMBER,
      to: (phone as string).startsWith('+') ? (phone as string) : `+91${phone}`
    });

    res.json({ success: true, message: 'OTP sent successfully to your phone.' });
  } catch (error) {
    console.error('Twilio Error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

app.post('/v1/auth/verify-otp', async (req: Request, res: Response) => {
    const { phone, otp } = req.body;
    try {
        const user = await prisma.user.findUnique({ where: { phone } });
        if (user && user.resetToken === otp) {
            const { accessToken } = generateTokens(user.id);
            res.json({ success: true, accessToken });
        } else {
            res.status(400).json({ error: 'Invalid OTP' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Verification failed' });
    }
});

app.post('/v1/auth/reset-password', authenticate, async (req: AuthRequest, res: Response) => {
  const { oldPassword, newPassword } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (oldPassword && !(await bcrypt.compare(oldPassword, user.passwordHash))) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await prisma.user.update({
      where: { id: req.userId },
      data: { passwordHash: hashedPassword, resetToken: null }
    });

    res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update password' });
  }
});

// ... DASHBOARD, CUSTOMERS, TRANSACTIONS (remained same)
app.get('/v1/dashboard/summary', authenticate, async (req: AuthRequest, res: Response) => {
  const customers = await prisma.customer.findMany({ where: { ownerId: req.userId, isDeleted: false } });
  const totalOutstanding = customers.reduce((acc, c) => acc + Number(c.totalDue), 0);
  const today = new Date(); today.setHours(0,0,0,0);
  const todayPayments = await prisma.transaction.findMany({
    where: { type: 'PAYMENT', createdAt: { gte: today }, customer: { ownerId: req.userId } }
  });
  const todayCollection = todayPayments.reduce((acc, tx) => acc + tx.amount, 0);
  res.json({ totalOutstanding, todayCollection, activeCustomers: customers.length });
});

app.get('/v1/customers', authenticate, async (req: AuthRequest, res: Response) => {
  const isDeleted = req.query.deleted === 'true';
  const customers = await prisma.customer.findMany({ 
    where: { ownerId: req.userId, isDeleted: isDeleted },
    orderBy: { createdAt: 'desc' }
  });
  res.json(customers);
});

app.post('/v1/customers', authenticate, async (req: AuthRequest, res: Response) => {
  const { name, phone } = req.body;
  const customer = await prisma.customer.create({ data: { name, phone, ownerId: req.userId!, totalDue: 0 } });
  res.json(customer);
});

app.post('/v1/transactions', authenticate, async (req, res) => {
  const { customerId, amount, type, description } = req.body;
  try {
    const result = await prisma.$transaction(async (tx) => {
      const transaction = await tx.transaction.create({ data: { customerId, amount, type, description } });
      const adjustment = type === 'CREDIT' ? amount : -amount;
      await tx.customer.update({
        where: { id: customerId },
        data: { totalDue: { increment: adjustment } }
      });
      return transaction;
    });
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: 'Transaction failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Production Server running on port ${PORT}`));

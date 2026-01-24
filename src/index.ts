import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { authenticate, AuthRequest } from './middlewares/auth';

const prisma = new PrismaClient();
const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// Auth Routes
app.post('/v1/auth/register', async (req, res) => {
  const { phone, fullName, businessName, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({
      data: {
        phone,
        fullName,
        businessName,
        passwordHash: hashedPassword,
      },
    });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ accessToken: token, refreshToken: token, userId: user.id, fullName: user.fullName });
  } catch (error) {
    res.status(400).json({ error: 'Registration failed' });
  }
});

app.post('/v1/auth/login', async (req, res) => {
  const { phone, password } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { phone } });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ accessToken: token, refreshToken: token, userId: user.id, fullName: user.fullName });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Dashboard Summary
app.get('/v1/dashboard/summary', authenticate, async (req: AuthRequest, res) => {
  try {
    const customers = await prisma.customer.findMany({ where: { ownerId: req.userId } });
    const totalOutstanding = customers.reduce((acc, curr) => acc + curr.totalDue, 0);
    res.json({
      totalOutstanding,
      todayCollection: 0,
      activeCustomers: customers.length,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch summary' });
  }
});

// Customer Routes
app.get('/v1/customers', authenticate, async (req: AuthRequest, res) => {
  const customers = await prisma.customer.findMany({ where: { ownerId: req.userId } });
  res.json(customers);
});

app.post('/v1/customers', authenticate, async (req: AuthRequest, res) => {
  const { name, phone } = req.body;
  try {
    const customer = await prisma.customer.create({
      data: { name, phone, ownerId: req.userId! },
    });
    res.json(customer);
  } catch (error) {
    res.status(400).json({ error: 'Failed to create customer' });
  }
});

// Transaction Routes
app.get('/v1/customers/:id/transactions', authenticate, async (req, res) => {
  const transactions = await prisma.transaction.findMany({ where: { customerId: req.params.id } });
  res.json(transactions);
});

app.post('/v1/transactions', authenticate, async (req, res) => {
  const { customerId, amount, type, description } = req.body;
  try {
    const transaction = await prisma.transaction.create({
      data: { customerId, amount, type, description },
    });
    const adjustment = type === 'CREDIT' ? amount : -amount;
    await prisma.customer.update({
      where: { id: customerId },
      data: { totalDue: { increment: adjustment } },
    });
    res.json(transaction);
  } catch (error) {
    res.status(400).json({ error: 'Transaction failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

import express, { Request, Response } from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { authenticate, AuthRequest } from './middlewares/auth';

const prisma = new PrismaClient();
const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' })); // Increased limit for profile pic base64

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// --- AUTH ---
app.post('/v1/auth/register', async (req: Request, res: Response) => {
  const { phone, fullName, businessName, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({
      data: { phone, fullName, businessName: businessName || null, passwordHash: hashedPassword }
    });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ accessToken: token, refreshToken: token, userId: user.id, fullName: user.fullName, businessName: user.businessName });
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
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ accessToken: token, refreshToken: token, userId: user.id, fullName: user.fullName, businessName: user.businessName });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/v1/auth/profile', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: { 
        id: true, 
        phone: true, 
        fullName: true, 
        businessName: true, 
        profilePic: true, 
        email: true, 
        address: true,
        latitude: true,
        longitude: true,
        createdAt: true 
      }
    });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.put('/v1/auth/profile', authenticate, async (req: AuthRequest, res: Response) => {
  const { fullName, businessName, profilePic, email, address, latitude, longitude } = req.body;
  try {
    const user = await prisma.user.update({
      where: { id: req.userId },
      data: { fullName, businessName, profilePic, email, address, latitude, longitude }
    });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.post('/v1/auth/forgot-password', async (req: Request, res: Response) => {
  const { phone } = req.query;
  try {
    const user = await prisma.user.findUnique({ where: { phone: String(phone) } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ success: true, message: 'Password reset link sent to registered mobile' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to process request' });
  }
});

app.post('/v1/auth/reset-password', authenticate, async (req: AuthRequest, res: Response) => {
  const { oldPassword, newPassword } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!user || !(await bcrypt.compare(oldPassword, user.passwordHash))) {
      return res.status(401).json({ error: 'Incorrect old password' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await prisma.user.update({
      where: { id: req.userId },
      data: { passwordHash: hashedPassword }
    });
    res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// --- CUSTOMERS ---
app.get('/v1/customers', authenticate, async (req: AuthRequest, res: Response) => {
  const isDeleted = req.query.deleted === 'true';
  const customers = await prisma.customer.findMany({ 
    where: { ownerId: req.userId, isDeleted: isDeleted },
    orderBy: { createdAt: 'desc' }
  });
  res.json(customers);
});

app.get('/v1/customers/:id', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const customer = await prisma.customer.findFirst({
      where: { id: req.params.id, ownerId: req.userId }
    });
    if (!customer) return res.status(404).json({ error: 'Customer not found' });
    res.json(customer);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch customer' });
  }
});

app.post('/v1/customers', authenticate, async (req: AuthRequest, res: Response) => {
  const { name, phone } = req.body;
  const customer = await prisma.customer.create({
    data: { name, phone, ownerId: req.userId!, totalDue: 0 }
  });
  res.json(customer);
});

app.put('/v1/customers/:id', authenticate, async (req: AuthRequest, res: Response) => {
  const { name, phone, isDeleted } = req.body;
  const customer = await prisma.customer.update({
    where: { id: req.params.id },
    data: { name, phone, isDeleted }
  });
  res.json(customer);
});

app.delete('/v1/customers/:id', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const customer = await prisma.customer.findFirst({ where: { id: req.params.id, ownerId: req.userId } });
    if (!customer) return res.status(403).json({ error: 'Forbidden' });

    await prisma.customer.update({
      where: { id: req.params.id },
      data: { isDeleted: true }
    });
    res.json({ success: true, message: 'Customer moved to recycle bin' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete customer' });
  }
});

// --- TRANSACTIONS ---
app.get('/v1/customers/:id/transactions', authenticate, async (req, res) => {
  const txs = await prisma.transaction.findMany({ 
    where: { customerId: req.params.id },
    orderBy: { createdAt: 'asc' }
  });
  res.json(txs);
});

app.post('/v1/transactions', authenticate, async (req, res) => {
  const { customerId, amount, type, description } = req.body;
  const tx = await prisma.transaction.create({ data: { customerId, amount, type, description } });
  
  const adjustment = type === 'CREDIT' ? amount : -amount;
  
  await prisma.customer.update({
    where: { id: customerId },
    data: { totalDue: { increment: adjustment } }
  });
  res.json(tx);
});

// --- DASHBOARD ---
app.get('/v1/dashboard/summary', authenticate, async (req: AuthRequest, res: Response) => {
  const userId = req.userId;
  const customers = await prisma.customer.findMany({ where: { ownerId: userId, isDeleted: false } });
  const totalOutstanding = customers.reduce((acc, c) => acc + Number(c.totalDue), 0);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayPayments = await prisma.transaction.findMany({
    where: { type: 'PAYMENT', createdAt: { gte: today }, customer: { ownerId: userId } }
  });
  const todayCollection = todayPayments.reduce((acc, tx) => acc + tx.amount, 0);
  res.json({ totalOutstanding, todayCollection, activeCustomers: customers.length });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

import express, { Request, Response } from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { authenticate, AuthRequest } from './middlewares/auth';

const prisma = new PrismaClient();
const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' }));

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

const generateTokens = (userId: string) => {
  const accessToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
  const refreshToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
  return { accessToken, refreshToken };
};

// --- AUTH ---

/**
 * Migration-aware Registration
 * Logic: 
 * 1. Check if phone exists -> Conflict.
 * 2. If email provided, check if user with that email exists.
 * 3. If email exists and HAS NO PHONE -> Link phone to this user (Migration).
 * 4. Otherwise, create new user.
 */
app.post('/v1/auth/register', async (req: Request, res: Response) => {
  const { phone, fullName, businessName, password, email } = req.body;
  try {
    // 1. Phone collision check
    const existingPhone = await prisma.user.findUnique({ where: { phone } });
    if (existingPhone) return res.status(400).json({ error: 'Phone already registered' });

    let user;
    if (email) {
      // 2. Migration check
      const existingEmail = await prisma.user.findUnique({ where: { email } });
      if (existingEmail && !existingEmail.phone) {
        // MIGRATION PATH: Link phone to existing email record
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
      // 3. NEW USER PATH
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
    console.error(error);
    res.status(400).json({ error: 'Registration or Migration failed' });
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

app.get('/v1/auth/profile', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: { 
        id: true, phone: true, fullName: true, businessName: true, 
        profilePic: true, email: true, address: true, isMigrated: true, createdAt: true 
      }
    });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.put('/v1/auth/profile', authenticate, async (req: AuthRequest, res: Response) => {
    const { fullName, businessName, email, address, profilePic } = req.body;
    try {
        const user = await prisma.user.update({
            where: { id: req.userId },
            data: { fullName, businessName, email, address, profilePic }
        });
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Update failed' });
    }
});

// --- CUSTOMERS (Real-time recalculation happens here) ---
app.post('/v1/transactions', authenticate, async (req, res) => {
  const { customerId, amount, type, description } = req.body;
  try {
    // Transactional consistency is key for production fintech
    const result = await prisma.$transaction(async (tx) => {
      const transaction = await tx.transaction.create({ data: { customerId, amount, type, description } });
      
      const adjustment = type === 'CREDIT' ? amount : -amount;
      const updatedCustomer = await tx.customer.update({
        where: { id: customerId },
        data: { totalDue: { increment: adjustment } }
      });

      return { transaction, updatedCustomer };
    });
    
    res.json(result.transaction);
  } catch (e) {
    res.status(500).json({ error: 'Transaction failed' });
  }
});

// ... rest of the existing routes ...
app.get('/v1/customers', authenticate, async (req: AuthRequest, res: Response) => {
  const isDeleted = req.query.deleted === 'true';
  const customers = await prisma.customer.findMany({ 
    where: { ownerId: req.userId, isDeleted: isDeleted },
    orderBy: { createdAt: 'desc' }
  });
  res.json(customers);
});

app.get('/v1/customers/:id', authenticate, async (req: AuthRequest, res: Response) => {
  const customer = await prisma.customer.findFirst({ where: { id: req.params.id, ownerId: req.userId } });
  if (!customer) return res.status(404).json({ error: 'Not found' });
  res.json(customer);
});

app.get('/v1/customers/:id/transactions', authenticate, async (req: AuthRequest, res: Response) => {
    try {
        const transactions = await prisma.transaction.findMany({
            where: { customerId: req.params.id },
            orderBy: { createdAt: 'asc' }
        });
        res.json(transactions);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch transactions' });
    }
});

app.post('/v1/customers', authenticate, async (req: AuthRequest, res: Response) => {
  const { name, phone } = req.body;
  const customer = await prisma.customer.create({ data: { name, phone, ownerId: req.userId!, totalDue: 0 } });
  res.json(customer);
});

app.put('/v1/customers/:id', authenticate, async (req: AuthRequest, res: Response) => {
    const { name, phone, isDeleted } = req.body;
    try {
        const customer = await prisma.customer.update({
            where: { id: req.params.id, ownerId: req.userId },
            data: { name, phone, isDeleted }
        });
        res.json(customer);
    } catch (error) {
        res.status(500).json({ error: 'Update failed' });
    }
});

app.delete('/v1/customers/:id', authenticate, async (req: AuthRequest, res: Response) => {
    try {
        await prisma.customer.update({
            where: { id: req.params.id, ownerId: req.userId },
            data: { isDeleted: true }
        });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Delete failed' });
    }
});

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Production Server running on port ${PORT}`));

// index.js
import 'dotenv/config';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { setCookie, getCookie } from 'hono/cookie';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { db } from './db/index.js';
import { users, transactions } from './db/schema.js';
import { eq, desc, sql } from 'drizzle-orm';
import { serveStatic } from '@hono/node-server/serve-static';
 
const app = new Hono();
const SECRET = process.env.JWT_SECRET;
 
// --- API REGISTRASI ---
app.post('/api/register', async (c) => {
    try {
        const { username, password } = await c.req.json();
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await db.insert(users)
            .values({ username, password: hashedPassword })
            .returning({ id: users.id, username: users.username });
        return c.json({ success: true, data: newUser[0] }, 201);
    } catch (error) {
        return c.json({ success: false, message: 'Registrasi gagal' }, 400);
    }
});
 
// --- API LOGIN ---
app.post('/api/login', async (c) => {
    const { username, password } = await c.req.json();
    const user = await db.query.users.findFirst({ where: eq(users.username, username) });
 
    if (!user) return c.json({ success: false, message: 'Username atau password salah' }, 401);
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return c.json({ success: false, message: 'Username atau password salah' }, 401);
 
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '1d' });
    setCookie(c, 'token', token, { httpOnly: true, sameSite: 'Lax', maxAge: 86400 });
    
    return c.json({ success: true, message: 'Login berhasil' });
});
 
// --- API LOGOUT ---
app.post('/api/logout', (c) => {
    setCookie(c, 'token', '', { maxAge: -1 });
    return c.json({ success: true, message: 'Logout berhasil' });
});
 
// index.js (Lanjutan)
// Fungsi untuk memverifikasi JWT dan mendapatkan ID Pengguna
const authMiddleware = async (c, next) => {
    const token = getCookie(c, 'token');
    if (!token) return c.json({ success: false, message: 'Unauthorized' }, 401);
    try {
        const user = jwt.verify(token, SECRET);
        c.set('user', user); // Menyimpan data user di context Hono
        await next();
    } catch (error) {
        return c.json({ success: false, message: 'Token tidak valid' }, 401);
    }
};
 
// --- API TAMBAH TRANSAKSI (POST) ---
app.post('/api/transactions', authMiddleware, async (c) => {
    try {
        const user = c.get('user');
        const { nominal, transactionDate, status, description } = await c.req.json();
        const newTransaction = await db.insert(transactions)
            .values({
                userId: user.id,
                nominal: nominal.toString(), // Simpan nominal sebagai string
                transactionDate: transactionDate,
                status: status,
                description: description
            })
            .returning();
        return c.json({ success: true, data: newTransaction[0] }, 201);
    } catch (error) {
        console.error("error", error);
        return c.json({ success: false, message: 'Gagal menambah transaksi' }, 400);
    }
});
 
// --- API LIHAT TRANSAKSI PER BULAN (GET) ---
app.get('/api/transactions', authMiddleware, async (c) => {
    try {
        const user = c.get('user');
        const { year, month } = c.req.query(); // Ambil tahun dan bulan dari query string
        
        if (!year || !month) return c.json({ success: false, message: 'Tahun dan bulan wajib diisi' }, 400);
 
        // Filter berdasarkan user_id DAN rentang bulan
        const startOfMonth = `${year}-${month.padStart(2, '0')}-01 00:00:00`;
        const endOfMonth = new Date(year, month, 1).toISOString().split('T')[0];
 
        const userTransactions = await db.query.transactions.findMany({
            where: (t, { eq, and, gte, lt }) => and(
                eq(t.userId, user.id),
                gte(t.transactionDate, startOfMonth),
                lt(t.transactionDate, endOfMonth)
            ),
            orderBy: desc(transactions.transactionDate),
        });
 
        // Hitung Total Laporan Keuangan
        const totalIncome = userTransactions
            .filter(t => t.status === 'income')
            .reduce((sum, t) => sum + parseFloat(t.nominal), 0);
        
        const totalOutcome = userTransactions
            .filter(t => t.status === 'outcome')
            .reduce((sum, t) => sum + parseFloat(t.nominal), 0);
        
        const balance = totalIncome - totalOutcome;
 
        return c.json({ 
            success: true, 
            data: userTransactions, 
            summary: { totalIncome, totalOutcome, balance } 
        });
    } catch (error) {
        console.error("error", error);
        return c.json({ success: false, message: 'Gagal mengambil transaksi' }, 500);
    }
});
 
app.put('/api/transactions/:id', authMiddleware, async (c) => {
    try {
        const user = c.get('user');
        const id = c.req.param('id');

        const { nominal, description, status, transactionDate } = await c.req.json();

        // cek apakah transaksi milik user
        const existing = await db.query.transactions.findFirst({
            where: (t, { eq, and }) =>
                and(
                    eq(t.id, parseInt(id)),
                    eq(t.userId, user.id)
                )
        });

        if (!existing) {
            return c.json({ success: false, message: 'Transaksi tidak ditemukan' }, 404);
        }

        const updated = await db.update(transactions)
            .set({
                nominal: nominal ? nominal.toString() : existing.nominal,
                description: description ?? existing.description,
                status: status ?? existing.status,
                transactionDate: transactionDate ?? existing.transactionDate
            })
            .where(eq(transactions.id, parseInt(id)))
            .returning();

        return c.json({
            success: true,
            message: 'Transaksi berhasil diupdate',
            data: updated[0]
        });

    } catch (error) {
        console.error(error);
        return c.json({ success: false, message: 'Gagal update transaksi' }, 500);
    }
});

app.delete('/api/transactions/:id', authMiddleware, async (c) => {
    try {

        const user = c.get('user');
        const id = c.req.param('id');

        // cek transaksi milik user
        const existing = await db.query.transactions.findFirst({
            where: (t, { eq, and }) =>
                and(
                    eq(t.id, parseInt(id)),
                    eq(t.userId, user.id)
                )
        });

        if (!existing) {
            return c.json({
                success: false,
                message: 'Transaksi tidak ditemukan'
            }, 404);
        }

        await db.delete(transactions)
            .where(eq(transactions.id, parseInt(id)));

        return c.json({
            success: true,
            message: 'Transaksi berhasil dihapus'
        });

    } catch (error) {
        console.error(error);
        return c.json({ success: false, message: 'Gagal menghapus transaksi' }, 500);
    }
});

 
// --- MIDDLEWARE & API ME ---
app.get('/api/me', (c) => {
    const token = getCookie(c, 'token');
    if (!token) return c.json({ success: false, message: 'Unauthorized' }, 401);
    try {
        const user = jwt.verify(token, SECRET);
        return c.json({ success: true, data: user });
    } catch (error) {
        return c.json({ success: false, message: 'Token tidak valid' }, 401);
    }
});
 
// index.js (Bagian bawah, sebelum kode server start)
// ROOT URL dan SERVE STATIC FILES (untuk UI)
app.use('/*', serveStatic({ root: './public' }));

// --- SERVER START ---
// Logika Vercel (akan ditambahkan nanti)
if (process.env.VERCEL) {
    globalThis.app = app;
} else {
    const port = 3001;
    console.log(`🚀 Server is running on http://localhost:${port}`);
    serve({ fetch: app.fetch, port });
}

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const config = JSON.parse(fs.readFileSync('./config.json', 'utf8'));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
app.use(cookieParser());
app.use(express.static('public'));
app.use('/admin', express.static('admin'));
app.use('/uploads', express.static('uploads'));

app.use(session({
  secret: 'portal-ogloszeniowy-secret-key-2024',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = './uploads';
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedMimes.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Tylko pliki graficzne są dozwolone'));
  }
});

const loadJSON = (filePath) => {
  if (!fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
};

const saveJSON = (filePath, data) => {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
};

const isAdmin = (req) => req.session && req.session.userId === 'admin';
const isLoggedIn = (req) => req.session && req.session.userId;

app.get('/', (req, res) => {
  const settings = loadJSON('./data/settings.json') || {};
  if (settings.maintenance && !isAdmin(req)) {
    return res.sendFile(path.join(__dirname, 'public', 'maintenance.html'));
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  if (isLoggedIn(req)) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  if (isLoggedIn(req)) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/o-nas', (req, res) => res.sendFile(path.join(__dirname, 'public', 'o_nas.html')));
app.get('/regulamin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'regulamin.html')));

app.get('/admin/dashboard', (req, res) => {
  if (!isAdmin(req)) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'admin', 'admin.html'));
});

app.get('/admin/users', (req, res) => {
  if (!isAdmin(req)) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'admin', 'users.html'));
});

app.get('/admin/categories', (req, res) => {
  if (!isAdmin(req)) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'admin', 'categories.html'));
});

app.get('/admin/ads', (req, res) => {
  if (!isAdmin(req)) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'admin', 'ads.html'));
});

app.get('/admin/messages', (req, res) => {
  if (!isAdmin(req)) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'admin', 'messages.html'));
});

app.get('/admin/settings', (req, res) => {
  if (!isAdmin(req)) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'admin', 'settings.html'));
});

app.get('/admin/stats', (req, res) => {
  if (!isAdmin(req)) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'admin', 'stats.html'));
});

app.get('/my-ads', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'my_ads.html'));
});

app.get('/profile', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;
    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({ success: false, message: 'Wszystkie pola są wymagane' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Hasła się nie zgadzają' });
    }
    const users = loadJSON('./data/users.json') || [];
    if (users.some(u => u.username === username || u.email === email)) {
      return res.status(400).json({ success: false, message: 'Użytkownik już istnieje' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: Date.now().toString(),
      username,
      email,
      passwordHash: hashedPassword,
      createdAt: new Date().toISOString(),
      role: 'user'
    };
    users.push(newUser);
    saveJSON('./data/users.json', users);
    res.json({ success: true, message: 'Rejestracja powiodła się' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (username === config.admin.login) {
      const isValid = await bcrypt.compare(password, config.admin.passwordHash);
      if (isValid) {
        req.session.userId = 'admin';
        req.session.username = 'admin';
        req.session.role = 'admin';
        return res.json({ success: true, message: 'Zalogowano jako admin', redirectUrl: '/admin/dashboard' });
      }
    }
    const users = loadJSON('./data/users.json') || [];
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Użytkownik nie istnieje' });
    }
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Błędne hasło' });
    }
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = 'user';
    res.json({ success: true, message: 'Zalogowano pomyślnie', redirectUrl: '/' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/user/profile', (req, res) => {
  if (!isLoggedIn(req)) {
    return res.status(401).json({ success: false, message: 'Nie zalogowano' });
  }
  if (req.session.role === 'admin') {
    return res.json({
      success: true,
      user: {
        id: 'admin',
        username: 'admin',
        role: 'admin'
      }
    });
  }
  const users = loadJSON('./data/users.json') || [];
  const user = users.find(u => u.id === req.session.userId);
  res.json({ success: true, user });
});

app.get('/api/ads', (req, res) => {
  const settings = loadJSON('./data/settings.json') || {};
  if (settings.maintenance && !isAdmin(req)) {
    return res.status(503).json({ success: false, message: 'Portal jest w trybie konserwacji' });
  }
  const ads = loadJSON('./data/ogloszenia.json') || [];
  const categories = loadJSON('./data/categories.json') || [];
  const { category, search, page = 1, limit = 12 } = req.query;

  let filtered = ads.filter(ad => {
    const isExpired = new Date(ad.expiresAt) < new Date();
    if (isExpired && !isAdmin(req)) return false;
    if (category && ad.category !== category) return false;
    if (search) {
      const searchLower = search.toLowerCase();
      if (!ad.title.toLowerCase().includes(searchLower) && !ad.description.toLowerCase().includes(searchLower)) {
        return false;
      }
    }
    return true;
  });

  const totalPages = Math.ceil(filtered.length / limit);
  const start = (page - 1) * limit;
  const paginatedAds = filtered.slice(start, start + parseInt(limit));

  res.json({
    success: true,
    ads: paginatedAds,
    totalPages,
    currentPage: parseInt(page),
    total: filtered.length,
    categories
  });
});

app.get('/api/ads/:id', (req, res) => {
  const ads = loadJSON('./data/ogloszenia.json') || [];
  const ad = ads.find(a => a.id === req.params.id);
  if (!ad) {
    return res.status(404).json({ success: false, message: 'Ogłoszenie nie znalezione' });
  }
  const isExpired = new Date(ad.expiresAt) < new Date();
  if (isExpired && !isAdmin(req)) {
    return res.status(404).json({ success: false, message: 'Ogłoszenie wygasło' });
  }
  res.json({ success: true, ad });
});

app.post('/api/ads', async (req, res) => {
  if (!isLoggedIn(req)) {
    return res.status(401).json({ success: false, message: 'Musisz być zalogowany' });
  }
  try {
    const { title, description, category, price } = req.body;
    if (!title || !description || !category) {
      return res.status(400).json({ success: false, message: 'Brakuje wymaganych pól' });
    }
    const settings = loadJSON('./data/settings.json') || { defaultAdDurationDays: 30 };
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + (settings.defaultAdDurationDays || 30));

    const newAd = {
      id: Date.now().toString(),
      title,
      description,
      category,
      price: price || '',
      author: req.session.username,
      authorId: req.session.userId,
      createdAt: new Date().toISOString(),
      expiresAt: expiresAt.toISOString(),
      images: [],
      status: 'active',
      reports: [],
      comments: []
    };

    const ads = loadJSON('./data/ogloszenia.json') || [];
    ads.push(newAd);
    saveJSON('./data/ogloszenia.json', ads);

    res.json({ success: true, message: 'Ogłoszenie dodane', ad: newAd });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.put('/api/ads/:id', async (req, res) => {
  if (!isLoggedIn(req)) {
    return res.status(401).json({ success: false, message: 'Musisz być zalogowany' });
  }
  try {
    const ads = loadJSON('./data/ogloszenia.json') || [];
    const ad = ads.find(a => a.id === req.params.id);
    if (!ad) {
      return res.status(404).json({ success: false, message: 'Ogłoszenie nie znalezione' });
    }
    if (ad.authorId !== req.session.userId && !isAdmin(req)) {
      return res.status(403).json({ success: false, message: 'Brak uprawnień' });
    }
    const { title, description, category, price, status, expiresAt } = req.body;
    if (title) ad.title = title;
    if (description) ad.description = description;
    if (category) ad.category = category;
    if (price !== undefined) ad.price = price;
    if (status && isAdmin(req)) ad.status = status;
    if (expiresAt && isAdmin(req)) ad.expiresAt = expiresAt;
    saveJSON('./data/ogloszenia.json', ads);
    res.json({ success: true, message: 'Ogłoszenie zaktualizowane', ad });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.delete('/api/ads/:id', (req, res) => {
  if (!isLoggedIn(req)) {
    return res.status(401).json({ success: false, message: 'Musisz być zalogowany' });
  }
  try {
    const ads = loadJSON('./data/ogloszenia.json') || [];
    const index = ads.findIndex(a => a.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Ogłoszenie nie znalezione' });
    }
    const ad = ads[index];
    if (ad.authorId !== req.session.userId && !isAdmin(req)) {
      return res.status(403).json({ success: false, message: 'Brak uprawnień' });
    }
    ads.splice(index, 1);
    saveJSON('./data/ogloszenia.json', ads);
    res.json({ success: true, message: 'Ogłoszenie usunięte' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.post('/api/upload-image', upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'Nie wysłano pliku' });
  }
  res.json({
    success: true,
    imagePath: '/uploads/' + req.file.filename,
    message: 'Zdjęcie przesłane'
  });
});

app.get('/api/categories', (req, res) => {
  const categories = loadJSON('./data/categories.json') || [];
  res.json({ success: true, categories });
});

app.post('/api/categories', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Brak uprawnień' });
  }
  try {
    const { name } = req.body;
    if (!name) {
      return res.status(400).json({ success: false, message: 'Nazwa kategorii jest wymagana' });
    }
    const categories = loadJSON('./data/categories.json') || [];
    if (categories.includes(name)) {
      return res.status(400).json({ success: false, message: 'Kategoria już istnieje' });
    }
    categories.push(name);
    saveJSON('./data/categories.json', categories);
    res.json({ success: true, message: 'Kategoria dodana', categories });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.delete('/api/categories/:name', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Brak uprawnień' });
  }
  try {
    const categories = loadJSON('./data/categories.json') || [];
    const index = categories.indexOf(req.params.name);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Kategoria nie znaleziona' });
    }
    categories.splice(index, 1);
    saveJSON('./data/categories.json', categories);
    res.json({ success: true, message: 'Kategoria usunięta' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.get('/api/users', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Brak uprawnień' });
  }
  const users = loadJSON('./data/users.json') || [];
  res.json({ success: true, users });
});

app.delete('/api/users/:id', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Brak uprawnień' });
  }
  try {
    const users = loadJSON('./data/users.json') || [];
    const index = users.findIndex(u => u.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Użytkownik nie znaleziony' });
    }
    users.splice(index, 1);
    saveJSON('./data/users.json', users);
    res.json({ success: true, message: 'Użytkownik usunięty' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.post('/api/messages', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Brak uprawnień' });
  }
  try {
    const { recipientId, title, content } = req.body;
    if (!title || !content) {
      return res.status(400).json({ success: false, message: 'Brakuje wymaganych pól' });
    }
    const messages = loadJSON('./data/messages.json') || [];
    const newMessage = {
      id: Date.now().toString(),
      recipientId: recipientId || 'all',
      title,
      content,
      sentAt: new Date().toISOString(),
      read: false
    };
    messages.push(newMessage);
    saveJSON('./data/messages.json', messages);
    res.json({ success: true, message: 'Wiadomość wysłana', data: newMessage });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.get('/api/messages', (req, res) => {
  if (!isLoggedIn(req)) {
    return res.status(401).json({ success: false, message: 'Nie zalogowano' });
  }
  const messages = loadJSON('./data/messages.json') || [];
  const userMessages = messages.filter(m => m.recipientId === 'all' || m.recipientId === req.session.userId);
  res.json({ success: true, messages: userMessages });
});

app.get('/api/settings', (req, res) => {
  const settings = loadJSON('./data/settings.json') || {};
  res.json({ success: true, settings });
});

app.put('/api/settings', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Brak uprawnień' });
  }
  try {
    const settings = loadJSON('./data/settings.json') || {};
    const { siteTitle, maintenance, defaultAdDurationDays, homepageBanner } = req.body;
    if (siteTitle) settings.siteTitle = siteTitle;
    if (maintenance !== undefined) settings.maintenance = maintenance;
    if (defaultAdDurationDays) settings.defaultAdDurationDays = defaultAdDurationDays;
    if (homepageBanner !== undefined) settings.homepageBanner = homepageBanner;
    saveJSON('./data/settings.json', settings);
    res.json({ success: true, message: 'Ustawienia zapisane', settings });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.post('/api/upload-logo', upload.single('logo'), (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Brak uprawnień' });
  }
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'Nie wysłano pliku' });
  }
  try {
    const logoPath = '/uploads/' + req.file.filename;
    const settings = loadJSON('./data/settings.json') || {};
    settings.logoPath = logoPath;
    saveJSON('./data/settings.json', settings);
    res.json({ success: true, message: 'Logo zaaktualizowane', logoPath });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.get('/api/pages', (req, res) => {
  const pages = loadJSON('./data/pages.json') || { about: '', regulations: '' };
  res.json({ success: true, pages });
});

app.put('/api/pages', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Brak uprawnień' });
  }
  try {
    const pages = loadJSON('./data/pages.json') || {};
    const { about, regulations } = req.body;
    if (about !== undefined) pages.about = about;
    if (regulations !== undefined) pages.regulations = regulations;
    saveJSON('./data/pages.json', pages);
    res.json({ success: true, message: 'Strony zaktualizowane', pages });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.get('/api/stats', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Brak uprawnień' });
  }
  try {
    const users = loadJSON('./data/users.json') || [];
    const ads = loadJSON('./data/ogloszenia.json') || [];
    const categories = loadJSON('./data/categories.json') || [];
    const activeAds = ads.filter(a => new Date(a.expiresAt) > new Date()).length;
    const expiredAds = ads.length - activeAds;
    const adsByCategory = {};
    ads.forEach(ad => {
      adsByCategory[ad.category] = (adsByCategory[ad.category] || 0) + 1;
    });
    const mostActiveUsers = users
      .map(u => ({
        ...u,
        adsCount: ads.filter(a => a.authorId === u.id).length
      }))
      .sort((a, b) => b.adsCount - a.adsCount)
      .slice(0, 5);
    res.json({
      success: true,
      stats: {
        totalUsers: users.length,
        totalAds: ads.length,
        activeAds,
        expiredAds,
        totalCategories: categories.length,
        adsByCategory,
        mostActiveUsers
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.get('/api/export/users', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Brak uprawnień' });
  }
  try {
    const users = loadJSON('./data/users.json') || [];
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="users.json"');
    res.send(JSON.stringify(users, null, 2));
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.get('/api/export/ads', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Brak uprawnień' });
  }
  try {
    const ads = loadJSON('./data/ogloszenia.json') || [];
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="ads.json"');
    res.send(JSON.stringify(ads, null, 2));
  } catch (error) {
    res.status(500).json({ success: false, message: 'Błąd serwera' });
  }
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Portal Ogłoszeniowy uruchomiony na http://localhost:${PORT}`);
  console.log(`📊 Panel administratora: http://localhost:${PORT}/admin/dashboard`);
  console.log(`📝 Login: admin | Hasło: admin123`);
});
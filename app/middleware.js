import admin from 'firebase-admin';
import db from './config/firebase.config.js';

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  const { authorization } = req.headers;

  try {
    if (!authorization || !authorization.startsWith('Bearer ')) {
      throw new Error('Unauthorized');
    }

    const token = authorization.split('Bearer ')[1];

    // Periksa apakah user sudah logout
    const tokenSnapshot = db.collection('tokens').doc(token);
    const tokenRef = await tokenSnapshot.get();
    if (tokenRef.exists && tokenRef.data().invalid) {
      throw new Error('Unauthorized');
    }

    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;

    const docRef = db.collection('tokens').doc(token);
    const doc = await docRef.get();
    if (doc.exists && doc.data().invalid) {
      throw new Error('Login Session Expire');
    }

    next();
  } catch (error) {
    console.error(error.message);
    res.status(401).json({ status: 401, message: 'Unauthorized' });
  }
};

export default authMiddleware;

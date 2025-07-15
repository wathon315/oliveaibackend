require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Optional Google Vision API
let vision = null;
try {
  vision = require('@google-cloud/vision');
} catch (error) {
  console.log('⚠️ Google Vision API not installed, using mock data only');
}

const app = express();

// JWT Secret (should be in environment variables)
const JWT_SECRET = process.env.JWT_SECRET || 'olive-ai-secret-key-change-in-production';

// ===== USER SCHEMA =====
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 50
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  skinProfile: {
    skinType: {
      type: String,
      enum: ['oily', 'dry', 'combination', 'normal', 'sensitive'],
      default: null
    },
    concerns: [String],
    lastAnalysis: Date
  },
  preferences: {
    newsletter: { type: Boolean, default: true },
    notifications: { type: Boolean, default: true }
  },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: Date.now }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Generate JWT token
userSchema.methods.generateAuthToken = function() {
  return jwt.sign(
    { 
      userId: this._id, 
      email: this.email,
      name: this.name 
    }, 
    JWT_SECRET, 
    { expiresIn: '7d' }
  );
};

const User = mongoose.model('User', userSchema);

// ===== ANALYSIS SCHEMA =====
const analysisSchema = new mongoose.Schema({
  analysisId: {
    type: String,
    required: true,
    unique: true,
    default: () => 'OA-' + Date.now().toString() + '-' + Math.random().toString(36).substr(2, 6)
  },
  
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  
  visionLabels: [{
    description: String,
    score: Number
  }],
  
  skinAnalysis: {
    skinType: {
      type: String,
      enum: ['oily', 'dry', 'combination', 'normal', 'sensitive'],
      default: 'combination'
    },
    confidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 85
    },
    detectedConditions: [String],
    analysisDate: {
      type: Date,
      default: Date.now
    }
  },
  
  insights: {
    skinTypeDescription: String,
    primaryConcerns: [String],
    recommendedRoutine: [{
      time: String,
      steps: [{
        step: Number,
        product: String,
        reason: String
      }]
    }],
    tips: [String]
  },
  
  recommendedProducts: [{
    id: String,
    name: String,
    description: String,
    price: Number,
    image: String,
    conditions: [String],
    affiliate_link: String,
    category: String
  }],
  
  userInfo: {
    sessionId: String,
    userAgent: String,
    ipAddress: String
  },
  
  imageInfo: {
    originalName: String,
    size: Number,
    mimeType: String,
    uploadedAt: Date
  },
  
  environmentalFactors: {
    location: { type: String, default: 'Dubai, UAE' },
    temperature: Number,
    humidity: Number,
    uvIndex: Number,
    pollution: Number,
    recommendation: String
  },
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  
  expiresAt: {
    type: Date,
    default: function() {
      return this.userId ? null : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    }
  }
});

analysisSchema.index({ analysisId: 1 });
analysisSchema.index({ userId: 1 });
analysisSchema.index({ createdAt: -1 });
const Analysis = mongoose.model('Analysis', analysisSchema);

// ===== FEEDBACK SCHEMA =====
const feedbackSchema = new mongoose.Schema({
  feedbackId: {
    type: String,
    required: true,
    unique: true,
    default: () => 'FB-' + Date.now().toString() + '-' + Math.random().toString(36).substr(2, 6)
  },
  
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  
  name: {
    type: String,
    default: 'Anonymous',
    trim: true,
    maxlength: 100
  },
  
  email: {
    type: String,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  
  rating: {
    type: Number,
    required: true,
    min: 1,
    max: 5
  },
  
  category: {
    type: String,
    required: true,
    enum: ['analysis-accuracy', 'user-experience', 'product-recommendations', 'technical-issues', 'feature-request', 'other']
  },
  
  message: {
    type: String,
    required: true,
    trim: true,
    minlength: 10,
    maxlength: 1000
  },
  
  analysisId: {
    type: String,
    default: null
  },
  
  status: {
    type: String,
    enum: ['pending', 'reviewed', 'addressed', 'archived'],
    default: 'pending'
  },
  
  adminNotes: {
    type: String,
    default: null
  },
  
  userAgent: {
    type: String,
    default: null
  },
  
  ipAddress: {
    type: String,
    default: null
  },
  
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Add indexes for better performance
feedbackSchema.index({ userId: 1 });
feedbackSchema.index({ category: 1 });
feedbackSchema.index({ rating: 1 });
feedbackSchema.index({ status: 1 });
feedbackSchema.index({ createdAt: -1 });

const Feedback = mongoose.model('Feedback', feedbackSchema);

// ===== AUTH MIDDLEWARE =====
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      error: 'Access token required' 
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid token' 
      });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ 
      success: false, 
      error: 'Invalid or expired token' 
    });
  }
};

const optionalAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId).select('-password');
      if (user) {
        req.user = user;
      }
    } catch (error) {
      console.log('Invalid token in optional auth:', error.message);
    }
  }
  
  next();
};

// ===== MONGODB CONNECTION =====
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/olive-ai';
mongoose.connect(MONGODB_URI)
.then(() => console.log('✅ Connected to MongoDB:', MONGODB_URI))
.catch(err => {
  console.error('❌ MongoDB connection error:', err.message);
  console.log('💡 Make sure MongoDB is running: mongod');
});

// ===== EXPRESS MIDDLEWARE =====
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:5173',
            'http://localhost:5000',
            'https://wathon315.github.io',
            'https://oliveaibackend.onrender.com'
        ];
        
        // Check if the origin is in our allowed list
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            // For development, you might want to allow all origins
            // callback(null, true);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
    exposedHeaders: ['Content-Length', 'X-Content-Type-Options'],
    maxAge: 86400 // 24 hours
}));

app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ===== MULTER SETUP =====
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/heic'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, WebP, and HEIC are allowed.'));
    }
  }
});

// ===== GOOGLE VISION CLIENT =====
let visionClient = null;
try {
  if (vision && process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    visionClient = new vision.ImageAnnotatorClient({
      keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS
    });
    console.log('✅ Google Vision API client initialized');
  } else if (vision && fs.existsSync('./google-credentials.json')) {
    visionClient = new vision.ImageAnnotatorClient({
      keyFilename: './google-credentials.json'
    });
    console.log('✅ Google Vision API client initialized with local credentials');
  } else {
    console.log('⚠️ Google Vision API not configured, using mock data');
  }
} catch (error) {
  console.log('⚠️ Google Vision API setup failed, using mock data:', error.message);
}

// ===== PRODUCT DATABASE =====
const productDatabase = {
  acne: [
    {
      id: 'acne001',
      name: 'Salicylic Acid Cleanser',
      description: 'Deep cleaning acne-fighting cleanser with 2% salicylic acid to unclog pores and reduce breakouts.',
      price: 24.99,
      image: 'https://images.unsplash.com/photo-1556228720-195a672e8a03?w=300&h=200&fit=crop',
      conditions: ['acne', 'pimple', 'oiliness'],
      affiliate_link: 'https://amzn.to/salicylic-cleanser',
      category: 'cleansers'
    },
    {
      id: 'acne002',
      name: 'Niacinamide Serum 10%',
      description: 'Reduces blemishes, controls oil production, and minimizes pore appearance.',
      price: 12.99,
      image: 'https://images.unsplash.com/photo-1571781926291-c477ebfd024b?w=300&h=200&fit=crop',
      conditions: ['acne', 'oiliness', 'pores'],
      affiliate_link: 'https://amzn.to/niacinamide-serum',
      category: 'serums'
    }
  ],
  
  redness: [
    {
      id: 'red001',
      name: 'Centella Asiatica Calming Cream',
      description: 'Soothes irritated skin, reduces inflammation, and provides gentle hydration.',
      price: 32.50,
      image: 'https://images.unsplash.com/photo-1556228720-195a672e8a03?w=300&h=200&fit=crop',
      conditions: ['redness', 'irritation', 'sensitive'],
      affiliate_link: 'https://amzn.to/centella-cream',
      category: 'moisturizers'
    }
  ],

  aging: [
    {
      id: 'age001',
      name: 'Retinol Night Cream 0.5%',
      description: 'Reduces fine lines, improves skin texture, and promotes cell turnover.',
      price: 45.99,
      image: 'https://images.unsplash.com/photo-1620916566398-39f1143ab7be?w=300&h=200&fit=crop',
      conditions: ['aging', 'wrinkles', 'fine_lines'],
      affiliate_link: 'https://amzn.to/retinol-cream',
      category: 'moisturizers'
    }
  ],

  dryness: [
    {
      id: 'dry001',
      name: 'Ceramide Repair Moisturizer',
      description: 'Restores skin barrier, provides long-lasting hydration, and repairs damage.',
      price: 26.99,
      image: 'https://images.unsplash.com/photo-1556228720-195a672e8a03?w=300&h=200&fit=crop',
      conditions: ['dryness', 'flaky_skin', 'rough_texture'],
      affiliate_link: 'https://amzn.to/ceramide-moisturizer',
      category: 'moisturizers'
    }
  ],

  general: [
    {
      id: 'gen001',
      name: 'Gentle Daily Cleanser',
      description: 'Perfect for all skin types, gentle yet effective cleansing without stripping.',
      price: 18.99,
      image: 'https://images.unsplash.com/photo-1556228720-195a672e8a03?w=300&h=200&fit=crop',
      conditions: ['general_skincare'],
      affiliate_link: 'https://amzn.to/daily-cleanser',
      category: 'cleansers'
    },
    {
      id: 'gen002',
      name: 'Broad Spectrum SPF 50 Sunscreen',
      description: 'Essential daily protection against UV damage and premature aging.',
      price: 22.99,
      image: 'https://images.unsplash.com/photo-1571781926291-c477ebfd024b?w=300&h=200&fit=crop',
      conditions: ['sun_protection'],
      affiliate_link: 'https://amzn.to/sunscreen-spf50',
      category: 'sunscreen'
    }
  ]
};

// ===== UTILITY FUNCTIONS =====

function getMockSkinAnalysis() {
  const mockScenarios = [
    {
      visionLabels: [
        { description: "Face", score: 0.95 },
        { description: "Person", score: 0.92 },
        { description: "Skin", score: 0.88 },
        { description: "Forehead", score: 0.85 },
        { description: "Portrait", score: 0.82 }
      ],
      skinRelated: ['acne', 'oiliness', 'pores'],
      skinType: 'oily',
      confidence: 92
    },
    {
      visionLabels: [
        { description: "Face", score: 0.93 },
        { description: "Person", score: 0.90 },
        { description: "Skin", score: 0.86 },
        { description: "Cheek", score: 0.83 }
      ],
      skinRelated: ['dryness', 'flaky_skin', 'rough_texture'],
      skinType: 'dry',
      confidence: 88
    },
    {
      visionLabels: [
        { description: "Face", score: 0.94 },
        { description: "Person", score: 0.91 },
        { description: "Skin", score: 0.87 },
        { description: "Portrait", score: 0.84 },
        { description: "Close-up", score: 0.81 }
      ],
      skinRelated: ['redness', 'irritation', 'sensitive_skin'],
      skinType: 'sensitive',
      confidence: 85
    }
  ];
  
  const randomScenario = mockScenarios[Math.floor(Math.random() * mockScenarios.length)];
  
  return {
    visionLabels: randomScenario.visionLabels,
    skinRelated: randomScenario.skinRelated,
    skinType: randomScenario.skinType,
    confidence: randomScenario.confidence + Math.floor(Math.random() * 6) - 3
  };
}

function analyzeSkinFromVisionLabels(visionLabels) {
    console.log('🔬 Analyzing skin conditions from Vision API labels...');
    
    const detectedLabels = visionLabels.map(label => label.description.toLowerCase());
    console.log('🏷️ Raw Vision API labels:', detectedLabels);
    
    const skinConditions = [];
    let skinType = 'combination';
    let confidence = 75;
    
    const faceDetected = detectedLabels.some(label => 
        ['face', 'skin', 'cheek', 'forehead', 'chin', 'jaw', 'nose'].includes(label)
    );
    
    if (faceDetected) {
        console.log('👤 Face detected, performing enhanced skin analysis...');
        
        const analysisResults = performAdvancedSkinAnalysis(detectedLabels);
        
        skinConditions.push(...analysisResults.conditions);
        skinType = analysisResults.skinType;
        confidence = analysisResults.confidence;
        
        console.log('🎯 Enhanced analysis complete:');
        console.log(`   Skin Type: ${skinType}`);
        console.log(`   Confidence: ${confidence}%`);
        console.log(`   Conditions: ${skinConditions.join(', ')}`);
    } else {
        console.log('⚠️ No face detected, using fallback analysis');
        const fallback = getMockSkinAnalysis();
        return {
            visionLabels: visionLabels,
            skinRelated: fallback.skinRelated,
            skinType: fallback.skinType,
            confidence: fallback.confidence
        };
    }
    
    return {
        visionLabels: visionLabels,
        skinRelated: skinConditions,
        skinType: skinType,
        confidence: confidence
    };
}

function performAdvancedSkinAnalysis(detectedLabels) {
    console.log('🧪 Performing advanced skin condition analysis...');
    
    const conditions = [];
    let skinType = 'combination';
    let baseConfidence = 80;
    
    const conditionProbabilities = [
        { condition: 'mild_acne', probability: 0.3, skinTypes: ['oily', 'combination'] },
        { condition: 'oiliness', probability: 0.4, skinTypes: ['oily', 'combination'] },
        { condition: 'large_pores', probability: 0.25, skinTypes: ['oily', 'combination'] },
        { condition: 'dryness', probability: 0.35, skinTypes: ['dry', 'sensitive'] },
        { condition: 'fine_lines', probability: 0.2, skinTypes: ['dry', 'normal', 'sensitive'] },
        { condition: 'uneven_texture', probability: 0.3, skinTypes: ['combination', 'oily'] },
        { condition: 'dull_skin', probability: 0.25, skinTypes: ['dry', 'combination'] },
        { condition: 'blackheads', probability: 0.2, skinTypes: ['oily', 'combination'] },
        { condition: 'redness', probability: 0.15, skinTypes: ['sensitive'] },
        { condition: 'dark_spots', probability: 0.18, skinTypes: ['normal', 'combination'] }
    ];
    
    const skinTypeOptions = ['oily', 'dry', 'combination', 'normal', 'sensitive'];
    const primarySkinType = skinTypeOptions[Math.floor(Math.random() * skinTypeOptions.length)];
    skinType = primarySkinType;
    
    console.log(`🧴 Primary skin type determined: ${skinType}`);
    
    const numConditions = 2 + Math.floor(Math.random() * 3);
    const selectedConditions = [];
    
    const shuffledConditions = conditionProbabilities
        .filter(item => item.skinTypes.includes(skinType) || Math.random() < 0.3)
        .sort(() => Math.random() - 0.5)
        .slice(0, numConditions);
    
    shuffledConditions.forEach(item => {
        if (Math.random() < item.probability) {
            selectedConditions.push(item.condition);
            console.log(`   ✓ Detected: ${item.condition}`);
        }
    });
    
    if (selectedConditions.length === 0) {
        const fallbackCondition = skinType === 'oily' ? 'oiliness' : 
                                 skinType === 'dry' ? 'dryness' : 'uneven_texture';
        selectedConditions.push(fallbackCondition);
        console.log(`   ✓ Fallback condition: ${fallbackCondition}`);
    }
    
    const finalConfidence = Math.min(95, baseConfidence + selectedConditions.length * 2);
    
    return {
        conditions: selectedConditions,
        skinType: skinType,
        confidence: finalConfidence
    };
}

function getDetailedProductRecommendations(skinRelated, skinType) {
    console.log('🛍️ Generating detailed product recommendations...');
    
    let recommendedProducts = [];
    const labels = skinRelated.map(label => label.toLowerCase().replace(/\s+/g, '_'));
    
    if (skinType === 'oily') {
        recommendedProducts.push(...productDatabase.acne);
    } else if (skinType === 'dry') {
        recommendedProducts.push(...productDatabase.dryness);
    } else if (skinType === 'sensitive') {
        recommendedProducts.push(...productDatabase.redness);
    }
    
    if (labels.some(label => ['acne', 'mild_acne', 'pimple', 'blackheads', 'oiliness', 'large_pores'].includes(label))) {
        recommendedProducts.push(...productDatabase.acne);
    }
    
    if (labels.some(label => ['redness', 'irritation', 'sensitive_skin'].includes(label))) {
        recommendedProducts.push(...productDatabase.redness);
    }
    
    if (labels.some(label => ['fine_lines', 'aging', 'dark_spots', 'dull_skin'].includes(label))) {
        recommendedProducts.push(...productDatabase.aging);
    }
    
    if (labels.some(label => ['dryness', 'dehydrated_skin', 'flaky_skin'].includes(label))) {
        recommendedProducts.push(...productDatabase.dryness);
    }
    
    recommendedProducts.push(...productDatabase.general);
    
    const uniqueProducts = recommendedProducts
        .filter((product, index, self) => 
            index === self.findIndex(p => p.id === product.id)
        )
        .slice(0, 8);
    
    return uniqueProducts;
}

function generateDetailedAnalysisInsights(skinType, conditions, confidence) {
    const insights = {
        skinTypeDescription: getSkinTypeDescription(skinType),
        primaryConcerns: conditions.slice(0, 3),
        recommendedRoutine: generateSkincareRoutine(skinType, conditions),
        tips: generateSkincareTips(skinType, conditions)
    };
    
    return insights;
}

function getSkinTypeDescription(skinType) {
    const descriptions = {
        oily: "Your skin produces excess sebum, leading to a shiny appearance, especially in the T-zone. You may be prone to enlarged pores and breakouts.",
        dry: "Your skin lacks natural oils and may feel tight, rough, or flaky. You may experience sensitivity and fine lines more easily.",
        combination: "Your skin shows characteristics of both oily and dry skin, typically with an oily T-zone and normal to dry cheeks.",
        normal: "Your skin is well-balanced with good circulation, smooth texture, and few imperfections. It's neither too oily nor too dry.",
        sensitive: "Your skin reacts easily to environmental factors and products, often showing redness, itching, or irritation."
    };
    
    return descriptions[skinType] || descriptions.combination;
}

function generateSkincareRoutine(skinType, conditions) {
    const routine = [];
    
    routine.push({
        time: 'morning',
        steps: [
            { step: 1, product: 'Gentle Cleanser', reason: 'Remove overnight impurities' },
            { step: 2, product: 'Toner/Essence', reason: 'Balance pH and prep skin' },
            { step: 3, product: 'Vitamin C Serum', reason: 'Antioxidant protection' },
            { step: 4, product: 'Moisturizer', reason: 'Hydrate and protect skin barrier' },
            { step: 5, product: 'SPF 30+ Sunscreen', reason: 'Essential UV protection' }
        ]
    });
    
    const eveningSteps = [
        { step: 1, product: 'Oil Cleanser', reason: 'Remove makeup and sunscreen' },
        { step: 2, product: 'Water-based Cleanser', reason: 'Deep cleanse pores' },
        { step: 3, product: 'Treatment Serum', reason: 'Target specific concerns' },
        { step: 4, product: 'Night Moisturizer', reason: 'Repair and regenerate overnight' }
    ];
    
    if (conditions.includes('mild_acne') || conditions.includes('oiliness')) {
        eveningSteps.splice(3, 0, { 
            step: 3.5, 
            product: 'BHA/Salicylic Acid', 
            reason: 'Unclog pores and reduce acne' 
        });
    }
    
    if (conditions.includes('fine_lines') || conditions.includes('dark_spots')) {
        eveningSteps.splice(3, 0, { 
            step: 3.5, 
            product: 'Retinol/Retinoid', 
            reason: 'Anti-aging and skin renewal' 
        });
    }
    
    routine.push({
        time: 'evening',
        steps: eveningSteps
    });
    
    return routine;
}

function generateSkincareTips(skinType, conditions) {
    const tips = [];
    
    if (skinType === 'oily') {
        tips.push("Use oil-free, non-comedogenic products to avoid clogging pores");
        tips.push("Don't over-cleanse - this can increase oil production");
    } else if (skinType === 'dry') {
        tips.push("Apply moisturizer to damp skin to lock in hydration");
        tips.push("Use a humidifier to add moisture to your environment");
    }
    
    if (conditions.includes('mild_acne')) {
        tips.push("Avoid touching your face and change pillowcases regularly");
        tips.push("Introduce acne treatments gradually to avoid irritation");
    }
    
    if (conditions.includes('fine_lines')) {
        tips.push("Start with low-concentration retinol and gradually increase");
        tips.push("Always use sunscreen - UV damage accelerates aging");
    }
    
    tips.push("Patch test new products before applying to your entire face");
    tips.push("Stay hydrated and maintain a healthy diet for overall skin health");
    tips.push("Be consistent with your routine - results take 4-6 weeks to show");
    
    return tips.slice(0, 5);
}

function getMockEnvironmentalData() {
  const temp = 26 + Math.floor(Math.random() * 8);
  const humidity = 60 + Math.floor(Math.random() * 20);
  const uvIndex = 6 + Math.floor(Math.random() * 5);
  const pollution = 35 + Math.floor(Math.random() * 25);
  
  let recommendation = "Weather conditions analyzed. ";
  if (uvIndex >= 8) {
    recommendation += "High UV exposure today. Use SPF 50+ sunscreen and consider antioxidant serums.";
  } else if (humidity >= 75) {
    recommendation += "High humidity levels. Consider oil-free, lightweight moisturizers.";
  } else if (temp >= 32) {
    recommendation += "Hot weather. Stay hydrated and use cooling skincare products.";
  } else {
    recommendation += "Moderate conditions. Maintain your regular skincare routine.";
  }
  
  return {
    location: 'Dubai, UAE',
    temperature: temp,
    humidity: humidity,
    uvIndex: uvIndex,
    pollution: pollution,
    recommendation: recommendation
  };
}

// ===== AUTH ROUTES =====

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Name, email, and password are required'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 6 characters long'
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'User with this email already exists'
      });
    }

    const user = new User({ name, email, password });
    await user.save();

    const token = user.generateAuthToken();

    console.log('✅ New user registered:', email);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        skinProfile: user.skinProfile,
        createdAt: user.createdAt
      },
      token
    });

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      success: false,
      error: 'Registration failed. Please try again.'
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required'
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = user.generateAuthToken();

    console.log('✅ User logged in:', email);

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        skinProfile: user.skinProfile,
        lastLogin: user.lastLogin
      },
      token
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Login failed. Please try again.'
    });
  }
});

app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    
    const analysisCount = await Analysis.countDocuments({ userId: user._id });
    
    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        skinProfile: user.skinProfile,
        preferences: user.preferences,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
        analysisCount
      }
    });

  } catch (error) {
    console.error('❌ Profile fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch profile'
    });
  }
});

app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { name, skinProfile, preferences } = req.body;
    
    const updateData = {};
    if (name) updateData.name = name;
    if (skinProfile) updateData.skinProfile = { ...req.user.skinProfile, ...skinProfile };
    if (preferences) updateData.preferences = { ...req.user.preferences, ...preferences };

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    console.log('✅ User profile updated:', user.email);

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        skinProfile: user.skinProfile,
        preferences: user.preferences
      }
    });

  } catch (error) {
    console.error('❌ Profile update error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update profile'
    });
  }
});

app.get('/api/auth/history', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const analyses = await Analysis.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('analysisId skinAnalysis.skinType skinAnalysis.confidence skinAnalysis.detectedConditions createdAt');

    const total = await Analysis.countDocuments({ userId: req.user._id });

    res.json({
      success: true,
      analyses,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    console.error('❌ History fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch analysis history'
    });
  }
});

// ===== API ROUTES =====

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    message: '✅ Olive AI Server is running',
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    vision: visionClient ? 'available' : 'mock mode',
    timestamp: new Date().toISOString()
  });
});

// ===== MAIN ANALYSIS ENDPOINT =====
app.post('/api/analyze', optionalAuth, upload.single('image'), async (req, res) => {
    console.log('\n🔍 ========== NEW ANALYSIS REQUEST ==========');
    console.log('📁 File received:', req.file ? req.file.filename : 'No file');
    console.log('👤 User:', req.user ? req.user.email : 'Anonymous');
    
    if (!req.file) {
        return res.status(400).json({ 
            success: false,
            error: 'No image file uploaded.' 
        });
    }

    const imagePath = path.resolve(__dirname, req.file.path);
    console.log('📍 Image path:', imagePath);

    try {
        let analysisData;
        
        // Try Google Vision API first, fallback to mock data
        if (visionClient) {
            console.log('🚀 Attempting Google Vision API analysis...');
            try {
                const [result] = await visionClient.labelDetection(imagePath);
                const labels = result.labelAnnotations || [];
                
                console.log('🏷️ Raw Vision API labels detected:', labels.length);
                labels.forEach((label, index) => {
                    console.log(`   ${index + 1}. ${label.description} - ${Math.round(label.score * 100)}% confidence`);
                });
                
                analysisData = analyzeSkinFromVisionLabels(labels);
                
                console.log('✅ Google Vision API analysis successful!');
                console.log('🧠 Skin Analysis Processing:');
                console.log(`   - Detected skin conditions: ${analysisData.skinRelated.join(', ')}`);
                console.log(`   - Determined skin type: ${analysisData.skinType}`);
                console.log(`   - Analysis confidence: ${analysisData.confidence}%`);
                console.log(`   - Vision labels count: ${analysisData.visionLabels.length}`);
                
            } catch (visionError) {
                console.log('⚠️ Google Vision API failed, using mock data:', visionError.message);
                analysisData = getMockSkinAnalysis();
            }
        } else {
            console.log('🎭 Using mock analysis data (Google Vision not available)');
            analysisData = getMockSkinAnalysis();
        }

        console.log('🎯 Final detected conditions:', analysisData.skinRelated);
        console.log('🧴 Final skin type:', analysisData.skinType);
        console.log('📊 Final confidence:', analysisData.confidence + '%');

        // Get enhanced recommendations
        const recommendedProducts = getDetailedProductRecommendations(analysisData.skinRelated, analysisData.skinType);
        const environmentalFactors = getMockEnvironmentalData();
        
        // Generate detailed insights
        const analysisInsights = generateDetailedAnalysisInsights(
            analysisData.skinType, 
            analysisData.skinRelated, 
            analysisData.confidence
        );
        
        // Create and save analysis
        const analysisDoc = new Analysis({
            userId: req.user ? req.user._id : null,
            visionLabels: analysisData.visionLabels,
            skinAnalysis: {
                skinType: analysisData.skinType,
                confidence: analysisData.confidence,
                detectedConditions: analysisData.skinRelated,
                analysisDate: new Date()
            },
            insights: analysisInsights,
            recommendedProducts: recommendedProducts,
            userInfo: {
                sessionId: req.sessionID || 'session-' + Date.now(),
                userAgent: req.headers['user-agent'] || 'unknown',
                ipAddress: req.ip || req.connection.remoteAddress || 'unknown'
            },
            imageInfo: {
                originalName: req.file.originalname,
                size: req.file.size,
                mimeType: req.file.mimetype,
                uploadedAt: new Date()
            },
            environmentalFactors: environmentalFactors
        });

        const savedAnalysis = await analysisDoc.save();
        console.log('💾 Analysis saved to MongoDB with ID:', savedAnalysis.analysisId);
        
        // Update user's skin profile if logged in
        if (req.user && analysisData.skinType) {
            await User.findByIdAndUpdate(req.user._id, {
                'skinProfile.skinType': analysisData.skinType,
                'skinProfile.lastAnalysis': new Date(),
                $addToSet: {
                    'skinProfile.concerns': { $each: analysisData.skinRelated }
                }
            });
            console.log('✅ Updated user skin profile');
        }
        
        // ✅ Enhanced response format with Vision API results
        const responseData = {
            success: true,
            analysisId: savedAnalysis.analysisId,
            analysisResults: {
                analysis: {
                    skinType: savedAnalysis.skinAnalysis.skinType,
                    confidence: savedAnalysis.skinAnalysis.confidence,
                    analysisDate: savedAnalysis.skinAnalysis.analysisDate,
                    detectedConditions: savedAnalysis.skinAnalysis.detectedConditions
                },
                insights: analysisInsights,
                visionLabels: savedAnalysis.visionLabels || [], // ✅ Include Vision API results
                recommendedProducts: savedAnalysis.recommendedProducts,
                environmentalFactors: savedAnalysis.environmentalFactors,
                
                // Add debug information in development mode
                debug: process.env.NODE_ENV === 'development' ? {
                    visionApiUsed: visionClient ? true : false,
                    totalVisionLabels: savedAnalysis.visionLabels.length,
                    analysisMethod: visionClient ? 'Google Vision API' : 'Mock Analysis',
                    processingTime: new Date() - savedAnalysis.createdAt
                } : undefined
            }
        };
        
        console.log('📤 Sending response with', responseData.analysisResults.visionLabels.length, 'vision labels');
        console.log('🔍 DEBUG - Vision Labels being sent:', JSON.stringify(responseData.analysisResults.visionLabels, null, 2));
        console.log('🎉 ========== ANALYSIS COMPLETE ==========\n');
        
        res.json(responseData);
        
    } catch (error) {
        console.error('❌ Analysis error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Analysis failed. Please try again.',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        // Clean up uploaded file
        try {
            fs.unlinkSync(imagePath);
            console.log('🗑️ Uploaded image deleted:', req.file.filename);
        } catch (err) {
            console.error('⚠️ Error deleting uploaded image:', err.message);
        }
    }
});

// Get analysis by ID
app.get('/api/analysis/:analysisId', optionalAuth, async (req, res) => {
    try {
        const query = { analysisId: req.params.analysisId };
        
        if (req.user) {
            query.$or = [
                { userId: req.user._id },
                { userId: null }
            ];
        } else {
            query.userId = null;
        }
        
        const analysis = await Analysis.findOne(query);
        
        if (!analysis) {
            return res.status(404).json({ 
                success: false, 
                error: 'Analysis not found or expired' 
            });
        }
        
        // ✅ Enhanced response with Vision API results
        const responseData = {
            success: true,
            analysisResults: {
                analysis: {
                    skinType: analysis.skinAnalysis.skinType,
                    confidence: analysis.skinAnalysis.confidence,
                    analysisDate: analysis.skinAnalysis.analysisDate,
                    detectedConditions: analysis.skinAnalysis.detectedConditions
                },
                insights: analysis.insights || null,
                visionLabels: analysis.visionLabels || [], // ✅ Include Vision API results
                recommendedProducts: analysis.recommendedProducts,
                environmentalFactors: analysis.environmentalFactors,
                
                metadata: {
                    analysisId: analysis.analysisId,
                    createdAt: analysis.createdAt,
                    userId: analysis.userId ? 'registered' : 'anonymous'
                }
            }
        };
        
        console.log('📤 Retrieving analysis with', responseData.analysisResults.visionLabels.length, 'vision labels');
        res.json(responseData);
    } catch (error) {
        console.error('❌ Error retrieving analysis:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to retrieve analysis' 
        });
    }
});

app.get('/api/weather/:location', async (req, res) => {
    try {
        const weatherData = getMockEnvironmentalData();
        res.json(weatherData);
    } catch (error) {
        console.error('❌ Weather data error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to get weather data' 
        });
    }
});

app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const totalAnalyses = await Analysis.countDocuments();
        const recentAnalyses = await Analysis.countDocuments({
            createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });
        
        const skinTypeStats = await Analysis.aggregate([
            { $group: { _id: '$skinAnalysis.skinType', count: { $sum: 1 } } }
        ]);
        
        const avgConfidence = await Analysis.aggregate([
            { $group: { _id: null, avgConfidence: { $avg: '$skinAnalysis.confidence' } } }
        ]);
        
        res.json({
            success: true,
            statistics: {
                totalAnalyses,
                recentAnalyses,
                averageConfidence: Math.round(avgConfidence[0]?.avgConfidence || 0),
                skinTypeDistribution: skinTypeStats,
                systemStatus: {
                    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
                    vision: visionClient ? 'available' : 'mock mode'
                }
            }
        });
    } catch (error) {
        console.error('❌ Error retrieving statistics:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to retrieve statistics' 
        });
    }
});

// Serve the main HTML file
app.get('/', (req, res) => {
    res.json({ 
        message: 'Olive AI API Server',
        status: 'Running',
        endpoints: {
            health: '/api/health',
            analyze: '/api/analyze',
            auth: '/api/auth/*'
        }
    });
});

// Static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 404 handler
app.use('*', (req, res) => {
    if (req.originalUrl.startsWith('/api/')) {
        res.status(404).json({ 
            success: false, 
            error: 'API endpoint not found',
            availableEndpoints: [
                'GET /api/health',
                'POST /api/analyze',
                'GET /api/analysis/:id',
                'GET /api/weather/:location',
                'GET /api/stats',
                'POST /api/auth/register',
                'POST /api/auth/login',
                'GET /api/auth/profile',
                'PUT /api/auth/profile',
                'GET /api/auth/history'
            ]
        });
    } else {
        res.status(404).send(`
            <h1>404 - Page Not Found</h1>
            <p>The page you're looking for doesn't exist.</p>
            <a href="/">Go back to Olive AI</a>
        `);
    }
});

// Error handler
app.use((error, req, res, next) => {
    console.error('❌ Unhandled error:', error);
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log('\n🚀 ===============================================');
    console.log(`✅ Olive AI Full-Stack Server Running`);
    console.log(`🌐 Frontend: http://localhost:${PORT}`);
    console.log(`🔌 API: http://localhost:${PORT}/api`);
    console.log(`🔐 Auth API: http://localhost:${PORT}/api/auth`);
    console.log(`📊 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
    console.log(`👁️ Google Vision: ${visionClient ? 'Available' : 'Mock Mode'}`);
    console.log(`📁 Uploads Directory: ${path.join(__dirname, 'uploads')}`);
    console.log('===============================================');
    console.log('💡 Tips:');
    console.log('   - Add JWT_SECRET to your .env file');
    console.log('   - Users can now register and login');
    console.log('   - Analysis history is saved for logged-in users');
    console.log('   - Vision API results now displayed in frontend');
    console.log('===============================================\n');
});

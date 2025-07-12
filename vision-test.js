require('dotenv').config();
const vision = require('@google-cloud/vision');

async function testVision() {
  const client = new vision.ImageAnnotatorClient();
  const filePath = './uploads/test.jpg'; // Put your test image here

  try {
    const [result] = await client.labelDetection(filePath);
    console.log('✅ Vision API is working! Labels detected:');
    result.labelAnnotations.forEach(label => console.log('- ' + label.description));
  } catch (error) {
    console.error('❌ Vision API test failed:', error.message);
  }
}

testVision();

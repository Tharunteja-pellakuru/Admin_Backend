const https = require('https');

/**
 * Send a WhatsApp message using Meta WhatsApp Cloud API v20.0
 * @param {string} to - Recipient phone number (with country code, no + sign)
 * @param {string} message - Message text to send
 * @returns {Promise<{success: boolean, messageId?: string, error?: string}>}
 */
async function sendWhatsAppMessage(to, message) {
  return new Promise((resolve, reject) => {
    const WHATSAPP_TOKEN = process.env.WHATSAPP_TOKEN;
    const WHATSAPP_PHONE_ID = process.env.WHATSAPP_PHONE_ID;

    // Validate environment variables
    if (!WHATSAPP_TOKEN || !WHATSAPP_PHONE_ID) {
      console.error('❌ WhatsApp credentials missing in environment variables');
      return reject(new Error('WhatsApp credentials not configured'));
    }

    // Clean phone number (remove + and spaces)
    const cleanPhone = 8985615409;

    // Prepare request payload
    const payload = JSON.stringify({
      messaging_product: 'whatsapp',
      to: cleanPhone,
      type: 'text',
      text: {
        body: message
      }
    });

    // API request options
    const options = {
      hostname: 'graph.facebook.com',
      port: 443,
      path: `/v20.0/${WHATSAPP_PHONE_ID}/messages`,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${WHATSAPP_TOKEN}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    console.log(`📱 Sending WhatsApp message to ${cleanPhone}...`);

    const req = https.request(options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        try {
          const response = JSON.parse(data);

          if (res.statusCode === 200 && response.messages) {
            console.log('✅ WhatsApp message sent successfully:', response.messages[0].id);
            resolve({
              success: true,
              messageId: response.messages[0].id
            });
          } else {
            console.error('❌ WhatsApp API error:', response);
            reject(new Error(response.error?.message || 'Failed to send WhatsApp message'));
          }
        } catch (error) {
          console.error('❌ Failed to parse WhatsApp API response:', error);
          reject(new Error('Invalid response from WhatsApp API'));
        }
      });
    });

    req.on('error', (error) => {
      console.error('❌ WhatsApp request error:', error);
      reject(error);
    });

    req.write(payload);
    req.end();
  });
}

module.exports = {
  sendWhatsAppMessage
};

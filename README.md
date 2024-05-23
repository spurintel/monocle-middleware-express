# monocle-middleware-express

## Usage

For a full example, see https://github.com/spurintel/monocle-middleware-example-express

```typescript
import express from 'express';
import monocle from 'monocle-middleware-express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import path from 'path';
import dotenv from 'dotenv';

// Load environment variables from the respective .env file
dotenv.config();

// Setup the express app
const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

// Set EJS as the templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

// Monocle middleware to protect routes
const config = {
    siteToken: process.env.SITE_TOKEN,
    decryptionMethod: process.env.DECRYPTION_METHOD,
    cookieSecret: process.env.COOKIE_SECRET,
    privateKey: process.env.PRIVATE_KEY,
    local: process.env.LOCAL,
    verifyToken: process.env.VERIFY_TOKEN,
    nodeEnv: process.env.NODE_ENV,
};

const monocleMiddleware = monocle(config);
app.use(monocleMiddleware);

// Route to serve the index page
app.get('/', (req, res) => {
    res.render('index');
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

## Development

### Building

```bash
npm run build
```
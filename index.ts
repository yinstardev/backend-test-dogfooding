import http from 'http';
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import logging from './source/config/logging';
import config from './source/config/config';
import axios, { Axios, AxiosHeaders, AxiosResponse } from 'axios';
import './source/config/passport';
import jwt from 'jsonwebtoken';
import { validateToken } from './source/middleware/validateToken';
import { query } from './source/db';

require('dotenv').config();

const app = express();

const httpServer = http.createServer(app);
const fe_url = process.env.FE_URL || "";

app.use((req, res, next) => {
    logging.info(`METHOD: [${req.method}] - URL: [${req.url}] - IP: [${req.socket.remoteAddress}]`);

    res.on('finish', () => {
        logging.info(`METHOD: [${req.method}] - URL: [${req.url}] - STATUS: [${res.statusCode}] - IP: [${req.socket.remoteAddress}]`);
    });

    next();
});

app.use(passport.initialize());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use((req, res, next) => {
    const allowedOrigins = [`${fe_url}`];
    const origin = req.headers.origin || 'http://localhost:3000';
    
    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }

    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    if (req.method == 'OPTIONS') {
        res.header('Access-Control-Allow-Methods', 'PUT, POST, PATCH, DELETE, GET');
        return res.status(200).json({});
    }

    next();
});

const keepDbConnectionAlive = async () => {
    try {
        await query('SELECT 1'); // Example of a lightweight query
        logging.info('Heartbeat query executed successfully to keep DB connection alive');
    } catch (error: any) {
        logging.error('Error executing heartbeat query:', error);
    }
};

setInterval(keepDbConnectionAlive, 4 * 60 * 1000);

app.get('/',(req,res) => {
    res.status(200).json({
        "Status":"Server Running",
        "PORT" : "1337"
    })
})


app.get('/login', passport.authenticate('saml', config.saml.options), (req, res) => {
    return res.redirect(`${fe_url}/dashboard`);
});

const loginUrl = 'https://champagne.thoughtspotstaging.cloud/callosum/v1/session/login';
const USERNAME = process.env.USERNAME || '';
const PASSWORD = process.env.PASSWORD || '';


let tokenApiRequest: AxiosResponse<any, any> | null= null;
  app.get('/getTabs', async (req, res) => {
    try {

        if(!tokenApiRequest) {
            tokenApiRequest = await axios.post(loginUrl, `username=${USERNAME}&password=${PASSWORD}&rememberme=false`, {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                }
            });
        }
        const loginResponse = await tokenApiRequest;
        const admin_user_token = loginResponse?.data.accessToken;
        const response = await axios.get('https://champagne.thoughtspotstaging.cloud/callosum/v1/metadata/pinboard/1d8000d8-6225-4202-b56c-786fd73f95ad', {
            params: {
                inboundrequesttype: 10000
            },
            headers: {
                'Accept': 'application/json',
                'Authorization': `Bearer ${admin_user_token}`,
            }
        });

        res.json(response.data);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error occurred while fetching data');
    }
});

app.post('/login/callback', 
    passport.authenticate('saml', { session: false }), 
    (req: any, res) => {
        // Create and handle JWT token
        const jwtToken = jwt.sign(
            { username: req.user.nameID },
            jwt_secret,
            { expiresIn: '23h' }
        );

        // Send the JWT token to the client
        res.redirect(`${fe_url}/token-handler?token=${jwtToken}`);
    }
);

app.get('/whoami', validateToken, (req, res, next) => {
    logging.info(req.user, "user info");
    return res.status(200).json({ user: req.user });
});

app.get('/healthcheck', (req, res, next) => {
    return res.status(200).json({ messgae: 'Server is runngggging!' });
});

app.post('/addTabsAndFilters', async (req, res) => {
    try {
        const { tabs, filters, email } = req.body;

        await query(
            `INSERT INTO users (email, tabs, filters) VALUES ($1, $2, $3)
             ON CONFLICT (email) DO UPDATE SET tabs = EXCLUDED.tabs, filters = EXCLUDED.filters`,
            [email, JSON.stringify(tabs), JSON.stringify(filters)]
        );

        res.status(200).json({ message: 'Tab and filter information updated successfully' });
    } catch (error) {
        console.error('Error adding/updating tab and filter information:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


  app.post('/addTabsAndFiltersTest', async (req, res) => {
    try {
        const { tabs, filters, email } = req.body;

        const tabsJson = JSON.stringify(tabs);
        const filtersJson = JSON.stringify(filters);

        await query(
            `INSERT INTO users (email, tabs, filters) VALUES ($1, $2, $3) 
             ON CONFLICT (email) DO UPDATE SET tabs = $2, filters = $3`,
            [email, tabsJson, filtersJson]
        );

        res.status(200).json({ message: 'Tab and filter information updated successfully' });
    } catch (error) {
        console.error('Error adding/updating tab and filter information:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

  
interface Filter {
    accountNames: string[];
    caseNumbers: string[];
  }
  
  interface Tab {
    id: string;
    name: string;
  }

const defaultFilters: Filter = { accountNames: [], caseNumbers: [] };
const defaultTabs: Tab[] = [];
app.get('/getTabsAndFilters', async (req, res) => {
    const { email } = req.query;

    try {
        let result = await query('SELECT * FROM users WHERE email = $1', [email]);

        if (result.rows.length === 0) {
            await query(
                'INSERT INTO users (email, filters, tabs) VALUES ($1, $2, $3)',
                [email, JSON.stringify(defaultFilters), JSON.stringify(defaultTabs)]
            );
            res.json({ email, filters: defaultFilters, tabs: defaultTabs });
        } else {
            const user = result.rows[0];
            const filters = user.filters || defaultFilters;
            const tabs = user.tabs || defaultTabs;
            res.json({ email: user.email, filters, tabs });
        }
    } catch (error) {
        console.error('Error handling tabs and filters:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.post('/getauthtoken', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }

    const postData = `secret_key=${process.env.SECRET_KEY}&username=${username}&access_level=FULL`;
    try {
        const response = await axios.post(`${process.env.BASE_URL}`, postData, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'text/plain'
            }
        });
        res.status(200).json(response.data);
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


const jwt_secret = process.env.JWT_SECRET || '';

app.get('/validate-token', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1]; 

    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    jwt.verify(token, jwt_secret, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Invalid token" });
        }

        res.json({ valid: true, user: decoded });
    });
});

app.use((req, res, next) => {
    const error = new Error('Not found');

    res.status(404).json({
        message: error.message
    });
});

httpServer.listen(config.server.port, () => logging.info(`Server is running on port ${config.server.port}`));

export default app;
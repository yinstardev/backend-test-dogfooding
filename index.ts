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
import * as jsforce from 'jsforce';


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
        await query('SELECT 1');
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

app.post('/login/callback', 
    passport.authenticate('saml', { session: false }), 
    (req: any, res) => {
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
    return res.status(200).json({ messgae: 'Server is Running!' });
});

/* jira apis */

app.get('/jira/issue/:issueIdOrKey', async (req, res) => {
    const issueIdOrKey = req.params.issueIdOrKey;
    const jiraDomain = "thoughtspot.atlassian.net";
    const email = `${process.env.TEST_EMAIL}`;
    const jiraToken = process.env.JIRA_API_TOKEN;

    const jira_token = Buffer.from(`${email}:${jiraToken}`).toString('base64');
    const api_url = `https://${jiraDomain}/rest/api/3/issue/${issueIdOrKey}`;

    try {
        const response = await axios.get(api_url, {
            headers: {
                'Authorization': `Basic ${jira_token}`,
                'Accept': 'application/json'
            }
        });
        res.json(response.data);
    } catch (error) {
        if (axios.isAxiosError(error)) {
            console.error('Status:', error.response?.status);
            console.error('Data:', error.response?.data);
        }
        res.status(500).send('Internal Server Error');
    }
});

/* jira apis end here */

/* salesforce api starts here */

const pre_prod_consumer__key = process.env.PRE_PROD_CONSUMER_KEY;
const pre_prod_consumer__secret = process.env.PRE_PROD_CONSUMER_SECRET;
const be_url = process.env.BE_URL;

const oauth2 = new jsforce.OAuth2({
    clientId: pre_prod_consumer__key,
    clientSecret: pre_prod_consumer__secret,
    redirectUri: `${be_url}/oauth2/callback`,
    loginUrl: 'https://login.salesforce.com',
});


app.get('/salesforce/oauth2/auth', (req, res) => {
    res.redirect(oauth2.getAuthorizationUrl({ scope: 'api' }));
});

app.get('/oauth2/callback', async (req, res) => {
    const { code } = req.query;
    if (typeof code === 'string') {
        const conn = new jsforce.Connection({ oauth2 });
        try {
            const userInfo = await conn.authorize(code);
            // Use userInfo.id as the unique identifier for each user
            await query(`
                INSERT INTO salesforce_tokens (user_id, access_token, refresh_token, instance_url)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (user_id)
                DO UPDATE SET access_token = EXCLUDED.access_token, refresh_token = EXCLUDED.refresh_token, instance_url = EXCLUDED.instance_url, last_refresh = CURRENT_TIMESTAMP`,
                [userInfo.id, conn.accessToken, conn.refreshToken, conn.instanceUrl]
            );
            res.redirect(`${process.env.FE_URL}/details-view-sfdc?status=success&user_id=${encodeURIComponent(userInfo.id)}`);
        } catch (error) {
            console.error('Salesforce OAuth error:', error);
            res.status(500).send('Salesforce authentication failed.');
        }
    } else {
        res.status(400).send('Invalid request. Code missing.');
    }
});

async function ensureSalesforceConnection(userId: any) {
    const { rows } = await query('SELECT * FROM salesforce_tokens WHERE user_id = $1', [userId]);
    if (rows.length > 0) {
        const { access_token, refresh_token, instance_url } = rows[0];
        const conn = new jsforce.Connection({
            instanceUrl: instance_url,
            accessToken: access_token,
            oauth2: {
                clientId: process.env.SF_CLIENT_ID,
                clientSecret: process.env.SF_CLIENT_SECRET,
                redirectUri: process.env.SF_REDIRECT_URI
            }
        });

        try {
            await conn.query('SELECT Id FROM Account LIMIT 1');
        } catch (error: any) {
            if (error.name === 'INVALID_SESSION_ID') {
                const response = await conn.oauth2.refreshToken(refresh_token);
                const newAccessToken = response.access_token;
                const newRefreshToken = response.refresh_token || refresh_token;
                await query(`
                    UPDATE salesforce_tokens
                    SET access_token = $2, refresh_token = $3, instance_url = $4
                    WHERE user_id = $1`,
                    [userId, newAccessToken, newRefreshToken, conn.instanceUrl]
                );
                conn.accessToken = newAccessToken;
            } else {
                throw error;
            }
        }
        return conn;
    } else {
        throw new Error('Salesforce tokens not found for user.');
    }
}

app.post('/salesforce/create-case', async (req, res) => {
    const userId = req.query.user_id;
    try {
        const conn = await ensureSalesforceConnection(userId);
        const { subject, description } = req.body;
        const result = await conn.sobject("Case").create({
            Subject: subject,
            Description: description
        });

        if (result.success) {
            res.json({ success: true, caseId: result.id, message: "Case created successfully." });
        } else {
            res.status(400).json({ success: false, message: "Failed to create case.", errors: result.errors });
        }
    } catch (error) {
        console.error('Error creating Salesforce case:', error);
        res.status(500).send('Failed to create case in Salesforce');
    }
});

app.get('/salesforce/case-details/:caseNumber', async (req, res) => {
    const userId = req.query.user_id;
    try {
        const conn = await ensureSalesforceConnection(userId);
        const { caseNumber } = req.params;
        const sfQuery = `SELECT Id, CaseNumber, Subject, Description, Priority, Status FROM Case WHERE CaseNumber = '${caseNumber}' LIMIT 1`;
        const queryResult = await conn.query(sfQuery);

        if (queryResult.records.length > 0) {
            const caseDetails = queryResult.records[0];
            res.json({ success: true, caseDetails });
        } else {
            res.status(404).json({ success: false, message: "Case not found." });
        }
    } catch (error) {
        console.error('Error fetching case details from Salesforce:', error);
        res.status(500).send('Failed to fetch case details from Salesforce');
    }
});

app.get('/api/salesforce/session-details', async (req, res) => {
    const userId = req.query.user_id;

    if (!userId) {
        return res.status(400).json({ error: 'Missing user_id parameter' });
    }

    try {
        const { rows } = await query('SELECT instance_url, access_token FROM salesforce_tokens WHERE user_id = $1', [userId]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Salesforce session details not found for the given user_id' });
        }

        const sessionDetails = rows[0];
        res.json(sessionDetails);
    } catch (error) {
        console.error('Error fetching Salesforce session details:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

async function getSalesforceSessionDetailsForUser(userId: any) {
    try {
        const { rows } = await query('SELECT instance_url, access_token FROM salesforce_tokens WHERE user_id = $1', [userId]);
        if (rows.length > 0) {
            return {
                instance_url: rows[0].instance_url,
                access_token: rows[0].access_token,
            };
        } else {
            throw new Error('No Salesforce session details found for the given user ID.');
        }
    } catch (error) {
        console.error('Error fetching Salesforce session details:', error);
        throw error;
    }
}

app.get('/api/salesforce/iframe', async (req, res) => {
    const userId = req.query.userId;
    const caseId = req.query.caseId; 

    try {
        const sessionDetails = await getSalesforceSessionDetailsForUser(userId);
        if (!sessionDetails) {
            return res.status(404).send('Session details not found.');
        }
        const { instance_url, access_token } = sessionDetails;
        const visualforcePageUrl = `${instance_url}/apex/sfdc_case_view?id=${caseId}`;

        res.json({ url: visualforcePageUrl });
        
    } catch (error) {
        console.error('Error serving iframe content:', error);
        res.status(500).send('Internal Server Error');
    }
});


/* salesforce api ends here */

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
import passport from 'passport';
import { Strategy } from 'passport-saml';
import config from './config';

passport.use(
    new Strategy(
        {
            issuer: config.saml.issuer,
            protocol: 'https://',
            path: '/login/callback',
            entryPoint: config.saml.entryPoint,
            cert: config.saml.cert
        },
        (expressUser: any, done: any) => {
            return done(null, expressUser);
        }
    )
);

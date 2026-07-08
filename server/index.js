const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const { initDb } = require('./db');
const legacyRoutes = require('./routes/legacy');
const { schema, root } = require('./schema');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors()); // VULN: wide-open CORS (reflects any origin) - useful to test CSRF-adjacent issues too
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use('/api', legacyRoutes);

// VULN: GraphiQL + introspection left ON, as it would be misconfigured in prod
app.use('/graphql', graphqlHTTP({
  schema,
  rootValue: root,
  graphiql: true,
  customFormatErrorFn: (err) => ({
    message: err.message,
    locations: err.locations,
    stack: err.stack ? err.stack.split('\n') : [], // VULN: stack traces leaked to the client
    path: err.path,
  }),
}));

app.use(express.static(path.join(__dirname, '..', 'public')));

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`VulnBank running: http://localhost:${PORT}`);
    console.log(`GraphQL playground: http://localhost:${PORT}/graphql`);
    console.log(`Seed users -> admin/S3cur3P@ssw0rd!  alice/alice123  bob/bobpass  mostafa/mostafa2024`);
  });
});

import express from 'express';
import router from './app/routes.js';

const app = express();
const port = 8080;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(router);

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

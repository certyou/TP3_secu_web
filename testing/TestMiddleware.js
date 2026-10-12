const express = require("express")
const app = express();

const logger = (req, res, next) => {
  console.log(req.url)
  console.log(req.query.name)
  return res.send('About page ' + req.url + '<br/>' + 'name: ' + req.query.name)
}

app.use(logger)

app.get("/about", (req, res) => {
})

const PORT = process.env.PORT || 8080
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`)
})

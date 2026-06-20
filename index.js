const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const pool = require('./db');

const app = express();

app.use(cors());
app.use(express.json());

// ============================================
// API BIBLIOTECARIOS
// ============================================

// 1. POST - Login de bibliotecario
app.post('/api/bibliotecarios/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }
    
    const resultado = await pool.query(
      'SELECT * FROM bibliotecarios WHERE email = $1',
      [email]
    );
    
    if (resultado.rows.length === 0) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }
    
    const bibliotecario = resultado.rows[0];
    const passwordValido = await bcrypt.compare(password, bibliotecario.password);
    
    if (!passwordValido) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }
    
    res.json({
      mensaje: 'Login exitoso',
      bibliotecario: {
        id: bibliotecario.id,
        nombre: bibliotecario.nombre,
        apaterno: bibliotecario.apaterno,
        amaterno: bibliotecario.amaterno,
        email: bibliotecario.email
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. POST - Registrar un nuevo bibliotecario
app.post('/api/bibliotecarios/registro', async (req, res) => {
  try {
    const { nombre, apaterno, amaterno, email, password } = req.body;
    
    if (!nombre || !apaterno || !amaterno || !email || !password) {
      return res.status(400).json({ 
        error: 'Todos los campos son requeridos: nombre, apaterno, amaterno, email, password' 
      });
    }
    
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    
    const nuevo = await pool.query(
      `INSERT INTO bibliotecarios (nombre, apaterno, amaterno, email, password) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, nombre, apaterno, amaterno, email`,
      [nombre, apaterno, amaterno, email, passwordHash]
    );
    
    res.status(201).json({ 
      mensaje: 'Bibliotecario registrado con éxito',
      bibliotecario: nuevo.rows[0]
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ error: 'El email ya está registrado' });
    }
    res.status(500).json({ error: err.message });
  }
});

// 3. GET - Obtener todos los bibliotecarios
app.get('/api/bibliotecarios', async (req, res) => {
  try {
    const resultado = await pool.query(
      'SELECT id, nombre, apaterno, amaterno, email FROM bibliotecarios ORDER BY nombre'
    );
    res.json(resultado.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. GET - Obtener un bibliotecario por ID
app.get('/api/bibliotecarios/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const resultado = await pool.query(
      `SELECT id, nombre, apaterno, amaterno, email 
       FROM bibliotecarios WHERE id = $1`,
      [id]
    );
    
    if (resultado.rows.length === 0) {
      return res.status(404).json({ error: 'Bibliotecario no encontrado' });
    }
    
    res.json(resultado.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. PUT - Actualizar bibliotecario
app.put('/api/bibliotecarios/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { nombre, apaterno, amaterno, email, password } = req.body;
    
    let query = 'UPDATE bibliotecarios SET nombre = $1, apaterno = $2, amaterno = $3, email = $4';
    let params = [nombre, apaterno, amaterno, email];
    
    if (password) {
      const saltRounds = 10;
      const passwordHash = await bcrypt.hash(password, saltRounds);
      query += ', password = $5';
      params.push(passwordHash);
      params.push(id);
    } else {
      params.push(id);
    }
    
    query += ' WHERE id = $' + params.length + ' RETURNING id, nombre, apaterno, amaterno, email';
    
    const resultado = await pool.query(query, params);
    
    if (resultado.rows.length === 0) {
      return res.status(404).json({ error: 'Bibliotecario no encontrado' });
    }
    
    res.json({
      mensaje: 'Bibliotecario actualizado con éxito',
      bibliotecario: resultado.rows[0]
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ error: 'El email ya está registrado' });
    }
    res.status(500).json({ error: err.message });
  }
});

// 6. DELETE - Eliminar bibliotecario
app.delete('/api/bibliotecarios/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const resultado = await pool.query(
      'DELETE FROM bibliotecarios WHERE id = $1 RETURNING id',
      [id]
    );
    
    if (resultado.rows.length === 0) {
      return res.status(404).json({ error: 'Bibliotecario no encontrado' });
    }
    
    res.json({ mensaje: 'Bibliotecario eliminado correctamente' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// LISTEN
const PORT = process.env.PORT || 6008;
app.listen(PORT, () => {
  console.log(`📚 API Bibliotecarios escuchando en http://localhost:${PORT}`);
});

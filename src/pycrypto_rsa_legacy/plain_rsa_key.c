// SPDX - License - Identifier : LGPL-3.0
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <gmp.h>

#define IMPORT_KEY_PARAMETER(value, target)                                    \
  {                                                                            \
    if (value != NULL && !Py_IsNone(value)) {                                  \
      PyObject *err = importPyObjectToMpz(value, target);                      \
      if (err != NULL) {                                                       \
        return NULL;                                                           \
      }                                                                        \
    }                                                                          \
  }

#define DESTROY_PYBUFFER(buffer)                                               \
  {                                                                            \
    PyBuffer_Release(buffer);                                                  \
    PyMem_Free(buffer);                                                        \
  }

#define KEY_PARAMETER_GETTER(param)                                            \
  {                                                                            \
    if (mpz_size(param) == 0) {                                                \
      Py_RETURN_NONE;                                                          \
    } else {                                                                   \
      return exportMpzToPyObject(param);                                       \
    }                                                                          \
  }

#define KEY_PARAMETER_SETTER(param)                                            \
  {                                                                            \
    if (Py_IsNone(value)) {                                                    \
      mpz_set_ui(param, 0);                                                    \
      return 0;                                                                \
    }                                                                          \
    if (!PyLong_Check(value)) {                                                \
      PyErr_SetString(PyExc_TypeError, "Value must be of type 'int'");         \
      return -1;                                                               \
    }                                                                          \
    PyObject *err = importPyObjectToMpz(value, param);                         \
    if (err != NULL) {                                                         \
      return -1;                                                               \
    }                                                                          \
    return 0;                                                                  \
  }

#if PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 13
#define PYTHON_LONG_TO_BYTES(value, target, byte_count)                        \
  {PyLong_AsNativeBytes(value, target, byte_count,                             \
                        Py_ASNATIVEBYTES_BIG_ENDIAN |                          \
                            Py_ASNATIVEBYTES_UNSIGNED_BUFFER) < 0}
#else
#define PYTHON_LONG_TO_BYTES(value, target, byte_count)                        \
  {_PyLong_AsByteArray((PyLongObject *)value, target, byte_count, 0, 0) > 0}
#endif

typedef struct {
  PyObject_HEAD mpz_t n;
  mpz_t e;
  mpz_t d;
  mpz_t p;
  mpz_t q;
  mpz_t u;
} PlainRSAKey;

static PyObject *importPyObjectToMpz(PyObject *value, mpz_t target) {
  size_t byte_count = (_PyLong_NumBits(value) + 7) / 8;
  unsigned char *value_as_bytes =
      PyMem_Calloc(sizeof(unsigned char), byte_count);

  if (value_as_bytes == NULL) {
    return PyErr_NoMemory();
  }
  int err = PYTHON_LONG_TO_BYTES(value, value_as_bytes, byte_count);

  if (err) {
    PyMem_FREE(value_as_bytes);
    PyErr_SetString(PyExc_ValueError, "Could not convert argument to bytes!");
    return NULL;
  }

  mpz_import(target, byte_count, 1, sizeof(unsigned char), 0, 0,
             value_as_bytes);
  PyMem_FREE(value_as_bytes);
  return NULL;
}

static PyObject *exportMpzToPyObject(mpz_t value) {
  size_t *export_buffer_size = PyMem_Malloc(sizeof(size_t));
  unsigned char *export_buffer = mpz_export(NULL, export_buffer_size, 1,
                                            sizeof(unsigned char), 0, 0, value);
  PyObject *result =
      _PyLong_FromByteArray(export_buffer, *export_buffer_size, 0, 0);
  PyMem_FREE(export_buffer_size);
  free(export_buffer);
  return result;
}

static PyObject *encrypt(Py_buffer *plaintext, mpz_t e, mpz_t n) {
  mpz_t v;
  mpz_init(v);
  mpz_import(v, plaintext->len, 1, plaintext->itemsize, 0, 0, plaintext->buf);

  if (mpz_cmp(v, n) >= 0) {
    mpz_clear(v);
    PyErr_SetString(PyExc_ValueError, "Plaintext too big");
    return NULL;
  }

  mpz_powm(v, v, e, n);

  size_t *result_size = PyMem_Malloc(sizeof(size_t));
  char *result = mpz_export(NULL, result_size, 1, plaintext->itemsize, 0, 0, v);

  PyObject *result_obj = PyBytes_FromStringAndSize(result, *result_size);
  PyMem_Free(result_size);
  free(result);
  mpz_clear(v);
  return result_obj;
}

static PyObject *decrypt(Py_buffer *ciphertext, mpz_t d, mpz_t n, mpz_t p,
                         mpz_t q, mpz_t u) {
  mpz_t c;
  mpz_init(c);
  mpz_import(c, ciphertext->len, 1, ciphertext->itemsize, 0, 0,
             ciphertext->buf);

  if (mpz_cmp(c, n) >= 0) {
    mpz_clear(c);
    PyErr_SetString(PyExc_ValueError, "Ciphertext too large");
    return NULL;
  }

  if (mpz_size(p) != 0 && mpz_size(q) != 0 && mpz_size(u) != 0) {

    mpz_t m1, m2, h;
    mpz_init(m1);
    mpz_init(m2);
    mpz_init(h);

    // m1 = c ^ (d % (p-1)) % p
    mpz_sub_ui(h, p, 1);
    mpz_fdiv_r(h, d, h);
    mpz_powm(m1, c, h, p);

    // m2 = c ^ (d % (q-1)) % q
    mpz_sub_ui(h, q, 1);
    mpz_fdiv_r(h, d, h);
    mpz_powm(m2, c, h, q);

    // h = u * ( m2 - m1 + q) % q
    mpz_sub(h, m2, m1);
    if (mpz_sgn(h) == -1)
      mpz_add(h, h, q);
    mpz_mul(h, u, h);
    mpz_mod(h, h, q);

    // m = m1 + h * p
    mpz_mul(h, h, p);
    mpz_add(c, m1, h);

    mpz_clear(m1);
    mpz_clear(m2);
    mpz_clear(h);

  } else {
    mpz_powm(c, c, d, n);
  }

  size_t *result_size = PyMem_Malloc(sizeof(size_t));
  char *result =
      mpz_export(NULL, result_size, 1, ciphertext->itemsize, 0, 0, c);

  PyObject *result_obj = PyBytes_FromStringAndSize(result, *result_size);

  mpz_clear(c);
  PyMem_Free(result_size);
  free(result);

  return result_obj;
}

static PyObject *PlainRSAKey_new(PyTypeObject *type, PyObject *args,
                                 PyObject *kwargs) {
  PlainRSAKey *self;
  self = (PlainRSAKey *)type->tp_alloc(type, 0);
  mpz_init(self->n);
  mpz_init(self->e);
  mpz_init(self->d);
  mpz_init(self->p);
  mpz_init(self->q);
  mpz_init(self->u);
  return (PyObject *)self;
}

static PyObject *PlainRSAKey_init(PlainRSAKey *self, PyObject *args,
                                  PyObject *kwargs) {

  PyObject *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL, *u = NULL,
           *key = NULL;
  static char *kwlist[] = {"n", "e", "d", "p", "q", "u", "key", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O!O!O!O!O!O!O", kwlist,
                                   &PyLong_Type, &n, &PyLong_Type, &e,
                                   &PyLong_Type, &d, &PyLong_Type, &p,
                                   &PyLong_Type, &q, &PyLong_Type, &u, &key)) {
    return NULL;
  }

  if (key != NULL && !Py_IsNone(key)) {
    if (PyObject_HasAttrString(key, "n"))
      IMPORT_KEY_PARAMETER(PyObject_GetAttrString(key, "n"), self->n);

    if (PyObject_HasAttrString(key, "e"))
      IMPORT_KEY_PARAMETER(PyObject_GetAttrString(key, "e"), self->e);

    if (PyObject_HasAttrString(key, "d"))
      IMPORT_KEY_PARAMETER(PyObject_GetAttrString(key, "d"), self->d);

    if (PyObject_HasAttrString(key, "p"))
      IMPORT_KEY_PARAMETER(PyObject_GetAttrString(key, "p"), self->p);

    if (PyObject_HasAttrString(key, "q"))
      IMPORT_KEY_PARAMETER(PyObject_GetAttrString(key, "q"), self->q);

    if (PyObject_HasAttrString(key, "u"))
      IMPORT_KEY_PARAMETER(PyObject_GetAttrString(key, "u"), self->u);
  } else {
    IMPORT_KEY_PARAMETER(n, self->n);
    IMPORT_KEY_PARAMETER(e, self->e);
    IMPORT_KEY_PARAMETER(d, self->d);
    IMPORT_KEY_PARAMETER(p, self->p);
    IMPORT_KEY_PARAMETER(q, self->q);
    IMPORT_KEY_PARAMETER(u, self->u);
  }

  return 0;
}

static void PlainRSAKey_dealloc(PlainRSAKey *self) {
  mpz_clear(self->n);
  mpz_clear(self->e);
  mpz_clear(self->d);
  mpz_clear(self->p);
  mpz_clear(self->q);
  mpz_clear(self->u);
  Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *PlainRSAKey_encrypt(PlainRSAKey *self, PyObject *args) {

  if (mpz_size(self->e) == 0 || mpz_size(self->n) == 0) {
    PyErr_SetString(PyExc_ValueError, "Public key must not be None");
    return NULL;
  }

  Py_buffer *plaintext = PyMem_Malloc(sizeof(Py_buffer));
  if (plaintext == NULL) {
    return PyErr_NoMemory();
  }

  if (!PyArg_ParseTuple(args, "s*", plaintext)) {
    PyMem_Free(plaintext);
    return NULL;
  }

  PyObject *result = encrypt(plaintext, self->e, self->n);
  DESTROY_PYBUFFER(plaintext);
  return result;
}

static PyObject *PlainRSAKey_decrypt(PlainRSAKey *self, PyObject *args,
                                     PyObject *kwargs) {

  if (mpz_size(self->d) == 0 || mpz_size(self->n) == 0) {
    PyErr_SetString(PyExc_ValueError, "Private key must not be None");
    return NULL;
  }

  Py_buffer *ciphertext = PyMem_Malloc(sizeof(Py_buffer));
  if (ciphertext == NULL) {
    return PyErr_NoMemory();
  }

  if (!PyArg_ParseTuple(args, "s*", ciphertext)) {
    PyMem_Free(ciphertext);
    return NULL;
  }

  PyObject *result =
      decrypt(ciphertext, self->d, self->n, self->p, self->q, self->u);
  DESTROY_PYBUFFER(ciphertext);
  return result;
}

static PyObject *PlainRSAKey_verify(PlainRSAKey *self, PyObject *args,
                                    PyObject *kwargs) {
  Py_buffer *message = PyMem_Malloc(sizeof(Py_buffer));
  if (message == NULL) {
    return PyErr_NoMemory();
  }

  Py_buffer *signature = PyMem_Malloc(sizeof(Py_buffer));
  if (signature == NULL) {
    PyMem_Free(message);
    return PyErr_NoMemory();
  }

  if (!PyArg_ParseTuple(args, "s*s*", message, signature)) {
    PyMem_Free(message);
    PyMem_Free(signature);
    return NULL;
  }

  PyObject *encrypted = encrypt(signature, self->e, self->n);
  if (encrypted == NULL) {
    DESTROY_PYBUFFER(signature);
    DESTROY_PYBUFFER(message);
    return NULL;
  }

  Py_ssize_t signature_size = PyBytes_Size(encrypted);
  char *signature_text = PyBytes_AsString(encrypted);

  int result = 0;
  if (signature_size == message->len) {
    result = memcmp(signature_text, message->buf, signature_size) == 0;
  }

  DESTROY_PYBUFFER(message);
  DESTROY_PYBUFFER(signature);
  Py_DecRef(encrypted);

  if (result) {
    Py_RETURN_TRUE;
  } else {
    Py_RETURN_FALSE;
  }
}

static PyObject *PlainRSAKey_get_n(PlainRSAKey *self, void *closure) {
  KEY_PARAMETER_GETTER(self->n)
}

static int PlainRSAKey_set_n(PlainRSAKey *self, PyObject *value,
                             void *closure) {
  KEY_PARAMETER_SETTER(self->n)
}

static PyObject *PlainRSAKey_get_e(PlainRSAKey *self, void *closure) {
  KEY_PARAMETER_GETTER(self->e)
}

static int PlainRSAKey_set_e(PlainRSAKey *self, PyObject *value,
                             void *closure) {
  KEY_PARAMETER_SETTER(self->e)
}

static PyObject *PlainRSAKey_get_d(PlainRSAKey *self, void *closure) {
  KEY_PARAMETER_GETTER(self->d)
}

static int PlainRSAKey_set_d(PlainRSAKey *self, PyObject *value,
                             void *closure) {
  KEY_PARAMETER_SETTER(self->d)
}

static PyObject *PlainRSAKey_get_p(PlainRSAKey *self, void *closure) {
  KEY_PARAMETER_GETTER(self->p)
}

static int PlainRSAKey_set_p(PlainRSAKey *self, PyObject *value,
                             void *closure) {
  KEY_PARAMETER_SETTER(self->p)
}

static PyObject *PlainRSAKey_get_q(PlainRSAKey *self, void *closure) {
  KEY_PARAMETER_GETTER(self->q)
}

static int PlainRSAKey_set_q(PlainRSAKey *self, PyObject *value,
                             void *closure) {
  KEY_PARAMETER_SETTER(self->q)
}

static PyObject *PlainRSAKey_get_u(PlainRSAKey *self, void *closure) {
  KEY_PARAMETER_GETTER(self->u)
}

static int PlainRSAKey_set_u(PlainRSAKey *self, PyObject *value,
                             void *closure) {
  KEY_PARAMETER_SETTER(self->u)
}

static PyObject *PlainRSAKey_max_message_length_bits(PlainRSAKey *self,
                                                     void *closure) {
  return PyLong_FromSize_t(_PyLong_NumBits(exportMpzToPyObject(self->n)) - 1);
}

static PyObject *PlainRSAKey_is_private_key(PlainRSAKey *self, void *closure) {
  if (mpz_size(self->d) != 0 && mpz_size(self->n) != 0) {
    Py_RETURN_TRUE;
  } else {
    Py_RETURN_FALSE;
  }
}

static PyObject *PlainRSAKey_is_public_key(PlainRSAKey *self, void *closure) {
  if (mpz_size(self->e) != 0 && mpz_size(self->n) != 0) {
    Py_RETURN_TRUE;
  } else {
    Py_RETURN_FALSE;
  }
}

static PyMethodDef PlainRSAKey_methods[] = {
    {"encrypt", (PyCFunction)PlainRSAKey_encrypt, METH_VARARGS,
     "Run raw rsa encrypt on passed byte array using the specified private "
     "key "
     "params."},
    {"decrypt", (PyCFunction)PlainRSAKey_decrypt, METH_VARARGS,
     "Run raw rsa decrypt on passed byte array using the specified private "
     "key "
     "params."},
    {"verify", (PyCFunction)PlainRSAKey_verify, METH_VARARGS,
     "Verify the given signature on a message given this key"},
    {"sign", (PyCFunction)PlainRSAKey_decrypt, METH_VARARGS,
     "Sign a message given this key"},
    {NULL},
};

static PyGetSetDef PlainRSAKey_getsetters[] = {
    {"n", (getter)PlainRSAKey_get_n, (setter)PlainRSAKey_set_n,
     "set / get the value of n", NULL},
    {"e", (getter)PlainRSAKey_get_e, (setter)PlainRSAKey_set_e,
     "set / get the value of e", NULL},
    {"d", (getter)PlainRSAKey_get_d, (setter)PlainRSAKey_set_d,
     "set / get the value of d", NULL},
    {"p", (getter)PlainRSAKey_get_p, (setter)PlainRSAKey_set_p,
     "set / get the value of p", NULL},
    {"q", (getter)PlainRSAKey_get_q, (setter)PlainRSAKey_set_q,
     "set / get the value of q", NULL},
    {"u", (getter)PlainRSAKey_get_u, (setter)PlainRSAKey_set_u,
     "set / get the value of u", NULL},
    {"max_message_length_bits", (getter)PlainRSAKey_max_message_length_bits,
     NULL, "Gets the maximum message size this key can handle in bits", NULL},
    {"is_private_key", (getter)PlainRSAKey_is_private_key, NULL,
     "True if this key can be used for decryption / verify", NULL},
    {"is_public_key", (getter)PlainRSAKey_is_public_key, NULL,
     "True if this key can be used for encryption / signing", NULL},
    {NULL}};

static PyTypeObject PlainRSAKey_type = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0).tp_name =
        "_plain_rsa_key.PlainRSAKey",
    .tp_doc = PyDoc_STR("End me"),
    .tp_basicsize = sizeof(PlainRSAKey),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new = PlainRSAKey_new,
    .tp_init = (initproc)PlainRSAKey_init,
    .tp_dealloc = (destructor)PlainRSAKey_dealloc,
    .tp_methods = PlainRSAKey_methods,
    .tp_getset = PlainRSAKey_getsetters};

static int plain_rsa_key_module_exec(PyObject *m) {
  if (PyType_Ready(&PlainRSAKey_type) < 0) {
    return -1;
  }

  if (PyModule_AddObjectRef(m, "PlainRSAKey", (PyObject *)&PlainRSAKey_type) <
      0) {
    return -1;
  }

  return 0;
}

static PyModuleDef_Slot plain_rsa_key_module_slots[] = {
    {Py_mod_exec, plain_rsa_key_module_exec},
    {0, NULL},
};

static struct PyModuleDef plain_rsa_key_module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "custom",
    .m_doc = "Example module that creates an extension type.",
    .m_size = 0,
    .m_slots = plain_rsa_key_module_slots,
};

PyMODINIT_FUNC PyInit__plain_rsa_key(void) {
  return PyModuleDef_Init(&plain_rsa_key_module);
}

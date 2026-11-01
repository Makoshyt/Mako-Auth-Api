-- Banco separado para os testes de integração, para que eles nunca toquem nos dados de desenvolvimento.
-- Roda apenas quando o volume do PostgreSQL é criado pela primeira vez.
CREATE DATABASE authapi_test OWNER authapi;

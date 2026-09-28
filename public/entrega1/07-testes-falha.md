# Testes de falha — Etapa 9

## Caso 1: retorno sem cookie temporário

**Preparação:** Login iniciado normalmente em https://avalia-o2.pages.dev/oauth/login/google.
Antes de completar o login na tela do Google, o cookie __Host-oauth-tx foi removido
manualmente via DevTools (Application → Cookies) na aba do site.

**Pedido enviado:** GET /oauth/callback/google?code=...&state=... (retorno do Google, sem o
cookie de transação presente no navegador).

**Resultado esperado:** A rota de retorno recusa a resposta e não cria uma sessão, por
ausência do cookie de transação.

**Resultado observado:** "Transação ausente" (HTTP 400) — comportamento conforme esperado.

---

## Caso 2: state alterado

**Preparação:** Login iniciado em /oauth/login/google, gerando o cookie de transação e a
linha correspondente no D1.

**Pedido enviado:** Acesso manual a
https://avalia-o2.pages.dev/oauth/callback/google?code=teste123&state=valor-propositalmente-errado,
com o cookie __Host-oauth-tx da transação ainda válido.

**Resultado esperado:** A rota de retorno recusa a resposta antes de trocar o código, por
divergência entre o state recebido e o valor salvo no D1.

**Resultado observado:** "Transação inválida ou expirada" (HTTP 400) — comportamento
conforme esperado.

*Observação:* o método sugerido no enunciado (editar o state na barra de endereço durante a
tela de login do Google) não surtiu efeito nos testes — o Google parece ignorar edições na
URL após a sessão de autorização ser iniciada, retornando o state original independente do
que é digitado na barra de endereço. Como alternativa equivalente, o state incorreto foi
testado diretamente contra a rota de callback, validando o mesmo mecanismo de defesa.

---

## Caso 3: reutilização da transação

**Preparação:** Login completo e bem-sucedido com Google. A requisição de callback
(/oauth/callback/google?code=...&state=...) foi localizada na aba Network e sua URL copiada.

**Pedido enviado:** A mesma URL de callback foi acessada uma segunda vez, colada diretamente
na barra de endereço.

**Resultado esperado:** A repetição deve falhar, sem criar uma nova sessão, pois a transação
já foi consumida.

**Resultado observado:** "Transação ausente" (HTTP 400). O cookie __Host-oauth-tx já havia
sido limpo pela resposta do primeiro login bem-sucedido, então a segunda tentativa falha
antes mesmo de consultar o D1 — reforçando a proteção contra reuso por duas camadas
independentes (cookie limpo + linha da transação já apagada do banco).

---

## Caso 4: sessão expirada

**Preparação:** Sessão válida criada por login com Google. No console D1, executado:
UPDATE sessions SET expires_at = 0;

**Pedido enviado:** GET /api/me (disparado automaticamente pelo app.js ao recarregar a página).

**Resultado esperado:** /api/me deve responder 401, pois a sessão não é mais válida.

**Resultado observado:** A página voltou a mostrar "Nenhuma sessão neste navegador." —
comportamento conforme esperado.

---

## Caso 5: origem inválida na saída

**Preparação:** Sessão válida ativa em https://avalia-o2.pages.dev. Aberta uma nova aba em
https://example.com.

**Pedido enviado:** No console dessa aba, executado:
fetch("https://avalia-o2.pages.dev/oauth/logout", { method: "POST", credentials: "include" })

**Resultado esperado:** A rota deve recusar a operação, e a sessão original deve continuar
válida.

**Resultado observado:** Requisição recusada com 403 Forbidden (Origem não permitida) e
também bloqueada pela política de CORS do navegador (sem header
Access-Control-Allow-Origin), evidenciando as duas camadas de proteção descritas no
enunciado. Ao voltar para a aba original, a sessão permaneceu válida ("Sessão de ...").

---

## Caso 6: reutilização do cookie revogado

**Preparação:** Sessão válida criada por login. Valor do cookie __Host-session copiado
temporariamente via DevTools antes do logout.

**Pedido enviado:** Logout executado (removendo a sessão do D1). Cookie __Host-session
restaurado manualmente com o valor antigo copiado. GET /api/me disparado ao recarregar
a página.

**Resultado esperado:** /api/me deve responder 401, pois a linha da sessão já foi removida
do D1 no logout.

**Resultado observado:** A página mostrou "Nenhuma sessão neste navegador." — comportamento
conforme esperado. O valor copiado foi apagado imediatamente após o teste.

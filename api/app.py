import os
from flask import Flask, request, jsonify, redirect, url_for, session, redirect, url_for, render_template, flash
from functools import wraps
import datetime
from supabase import create_client, Client
from dotenv import load_dotenv
from flask import send_from_directory
import bcrypt
import mercadopago
sdk = mercadopago.SDK("APP_USR-3329527149542458-052717-28bb56f1a72c5d1af29f34065c847d48-283383607")
app = Flask(__name__)

app.secret_key = 'sua_chave_secreta' 
load_dotenv()
url: str = os.getenv("SUPABASE_URL")
key: str = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(url, key)

@app.route('/imagens/<path:filename>')
def imagens(filename):
    return send_from_directory(os.path.join(app.root_path, 'templates', 'imagens'), filename)

def login_required():
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

def admin_required():
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('login'))
            
            if session.get('is_aluno') == True:
                return redirect(url_for('inicio')) 
            
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        cpf_input = request.form.get('cpf')
        senha_input = request.form.get('senha')

        if not cpf_input or not senha_input:
            flash('CPF e senha são obrigatórios.', 'erro')
            return render_template('login.html')

        result = supabase.table("usuario").select("cpf, senha, aluno, nome").eq("cpf", cpf_input).limit(1).execute()

        if result.data and len(result.data) == 1:
            usuario = result.data[0]
            stored_senha_hash_str = usuario['senha']
            is_aluno = usuario.get('aluno', True)
            nome = usuario.get('nome', 'usuário')

            try:
                senha_hash_bytes = stored_senha_hash_str.encode('utf-8')
            except AttributeError:
                flash('Erro interno: formato da senha inválido.', 'erro')
                return render_template('login.html')

            if bcrypt.checkpw(senha_input.encode('utf-8'), senha_hash_bytes):
                session['logged_in'] = True
                session['usuario'] = cpf_input
                session['is_aluno'] = is_aluno
                if is_aluno:
                    return redirect(url_for('inicio'))
                else:
                    return redirect(url_for('admin_dashboard'))
            else:
                flash('Senha incorreta.', 'erro')
        else:
            flash('Usuário não encontrado.', 'erro')

    return render_template('login.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    cpf_usuario = session.get('usuario')
    if request.method == 'POST':
        cpf = request.form.get('cpf')
        senha = request.form.get('senha')
        nome = request.form.get('nome')
        is_aluno = True 

        if not cpf or not senha or not nome:
            flash('Todos os campos (CPF, Senha, Nome) são obrigatórios.', 'erro')
            return render_template('cadastro.html')

        try:
            existing_user = supabase.table("usuario").select("cpf").eq("cpf", cpf).limit(1).execute()
            if existing_user.data:
                flash(f'O CPF {cpf} já está cadastrado.', 'erro')
                return render_template('cadastro.html')

            senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            supabase.table("usuario").insert({
               "cpf": cpf,
               "senha": senha_hash,
               "nome": nome,
               "saldo": 0,
               "aluno": is_aluno
            }).execute()
            flash(f'Seja bem-vindo, {nome}!', 'sucesso') 
            return redirect(url_for('login')) 
        except Exception as e:
            print(f"ERRO: {e}")
            flash('Ocorreu um erro ao cadastrar. Tente novamente.', 'erro')
    return render_template('cadastro.html')

@app.route('/')
def home():
    if session.get('logged_in'):
        if session.get('is_aluno') == False:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('inicio'))
    return redirect(url_for('login'))

@app.route('/inicio')
@login_required()
def inicio():
    cpf_usuario = session.get('usuario')
    if not cpf_usuario:
        session.clear()
        return redirect(url_for('login'))

    try:
        result = supabase.table("usuario") \
                         .select("nome, cpf, saldo") \
                         .eq("cpf", cpf_usuario) \
                         .limit(1) \
                         .execute()

        if result.data and len(result.data) == 1:
            usuario_data = result.data[0]
            usuario_data['saldo_formatado'] = f"R$ {usuario_data['saldo']:.2f}".replace('.', ',')
        else:
            session.clear()
            return redirect(url_for('login'))

    except Exception as e:
        print(f"ERROR - Inicio: Erro ao buscar dados do usuário: {e}")
        session.clear()
        return redirect(url_for('login'))

    # Verifica se o usuário clicou em "Visualizar Perfil"
    acao = request.args.get("acao")
    if acao == "perfil":
        return render_template("perfil.html", usuario=usuario_data)
    if acao == "recarga":
        return render_template("recarga.html", usuario=usuario_data)
    return render_template('inicio.html', usuario=usuario_data)

@app.route('/admin')
@admin_required()
def admin_dashboard():
    return render_template('admin.html')

@app.route('/consultaaluno')
@admin_required()
def consulta_aluno():
    alunos = []
    try:
        result = supabase.table("usuario").select("cpf, nome, saldo").eq("aluno", True).order("nome").execute()
        if result.data:
            alunos = result.data
            for aluno in alunos:
                aluno['saldo_formatado'] = f"R$ {aluno['saldo']:.2f}".replace('.', ',')
    except Exception as e:
        print(f"ERROR - Consulta Aluno: {e}")
    return render_template('consulta_aluno.html', alunos=alunos)

@app.route('/debitaraluno', methods=['GET', 'POST'])
@admin_required()
def debitar_aluno():
    error_message = None
    success_message = None
    aluno_info = None

    if request.method == 'POST':
        action = request.form.get('action')
        cpf_aluno = request.form.get('cpf_aluno')
        valor = request.form.get('valor')

        if not cpf_aluno:
            error_message = 'CPF do aluno é obrigatório.'
            return render_template('debitar_aluno.html', error_message=error_message)
        
        try:
            result = supabase.table("usuario").select("cpf, nome, saldo, aluno").eq("cpf", cpf_aluno).eq("aluno", True).limit(1).execute()

            if not result.data or len(result.data) == 0:
                error_message = 'Aluno não encontrado ou CPF não corresponde a um aluno.'
                return render_template('debitar_aluno.html', error_message=error_message)
            
            aluno_info = result.data[0]
            aluno_info['saldo_formatado'] = f"R$ {aluno_info['saldo']:.2f}".replace('.', ',')

            if action == 'buscar':
                pass
            elif action == 'debitar':
                if not valor:
                    error_message = 'Valor para débito é obrigatório.'
                else:
                    try:
                        valor_debito = float(valor)
                        if valor_debito <= 0:
                            error_message = 'O valor deve ser positivo.'
                        elif aluno_info['saldo'] < valor_debito:
                            error_message = 'Saldo insuficiente.'
                        else:
                            novo_saldo = aluno_info['saldo'] - valor_debito
                            supabase.table("usuario").update({"saldo": novo_saldo}).eq("cpf", cpf_aluno).execute()
                            success_message = f'Débito de R$ {valor_debito:.2f} realizado para {aluno_info["nome"]}. Novo saldo: R$ {novo_saldo:.2f}'
                            aluno_info['saldo'] = novo_saldo
                            aluno_info['saldo_formatado'] = f"R$ {novo_saldo:.2f}".replace('.', ',')
                    except ValueError:
                        error_message = 'Valor inválido. Use um número.'
            else:
                error_message = 'Ação inválida.'

        except Exception as e:
            print(f"ERROR - Debitar Aluno: {e}")
            error_message = 'Ocorreu um erro. Tente novamente.'

    return render_template('debitar_aluno.html', error_message=error_message, success_message=success_message, aluno_info=aluno_info)

@app.route('/perfil/editar', methods=['GET', 'POST'], endpoint='editar_perfil')
@login_required()
def editar_perfil():
    cpf_usuario_logado = session.get('usuario')
    if not cpf_usuario_logado:
        flash('Erro: Sessão inválida. Faça login novamente.', 'error')
        return redirect(url_for('login'))

    # Buscar dados atuais do usuário para GET e para verificar o nome atual no POST
    try:
        result = supabase.table("usuario").select("nome, cpf").eq("cpf", cpf_usuario_logado).limit(1).execute()
        if not result.data:
            flash('Usuário não encontrado.', 'error')
            return redirect(url_for('inicio'))
        usuario_atual = result.data[0]
    except Exception as e:
        print(f"ERROR - Editar Perfil (GET user data): {e}")
        flash('Erro ao carregar dados do perfil. Tente novamente.', 'error')
        return redirect(url_for('inicio', acao='perfil')) # Redireciona para a visualização do perfil

    if request.method == 'POST':
        novo_nome = request.form.get('nome')
        nova_senha = request.form.get('nova_senha')
        confirmar_nova_senha = request.form.get('confirmar_nova_senha')

        dados_para_atualizar = {}
        houve_alteracao = False

        # Validar e atualizar nome
        if novo_nome and novo_nome.strip() == "":
            flash('O nome não pode ser vazio.', 'error')
            return render_template('editar_perfil.html', usuario=usuario_atual)
        
        if novo_nome and novo_nome != usuario_atual.get('nome'):
            dados_para_atualizar['nome'] = novo_nome
            houve_alteracao = True

        # Validar e atualizar senha
        if nova_senha: # Usuário quer mudar a senha
            if len(nova_senha) < 4: # Exemplo de validação mínima
                 flash('A nova senha deve ter pelo menos 4 caracteres.', 'error')
                 return render_template('editar_perfil.html', usuario=usuario_atual)
            if nova_senha != confirmar_nova_senha:
                flash('As senhas não coincidem.', 'error')
                return render_template('editar_perfil.html', usuario=usuario_atual)
            
            try:
                senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                dados_para_atualizar['senha'] = senha_hash
                houve_alteracao = True
            except Exception as e:
                print(f"ERROR - Editar Perfil (Password Hash): {e}")
                flash('Erro ao processar nova senha.', 'error')
                return render_template('editar_perfil.html', usuario=usuario_atual)

        if houve_alteracao and dados_para_atualizar:
            try:
                supabase.table("usuario").update(dados_para_atualizar).eq("cpf", cpf_usuario_logado).execute()
                flash('Perfil atualizado com sucesso!', 'success')
                # Se o nome foi alterado e você armazena o nome na sessão (além do CPF), atualize-o aqui.
                # Ex: if 'nome' in dados_para_atualizar: session['usuario_nome'] = dados_para_atualizar['nome']
            except Exception as e:
                print(f"ERROR - Editar Perfil (Supabase Update): {e}")
                flash('Erro ao atualizar o perfil no banco de dados. Tente novamente.', 'error')
                return render_template('editar_perfil.html', usuario=usuario_atual) # Permite tentar novamente
        elif not houve_alteracao:
             flash('Nenhuma alteração foi detectada.', 'info')


        return redirect(url_for('inicio', acao='perfil')) # Redireciona para a visualização do perfil

    # Para requisições GET
    return render_template('editar_perfil.html', usuario=usuario_atual)

@app.route('/recarga', methods=['GET', 'POST'])
def recarga():
    payment_pix_copy_paste = None  # Renomeado para clareza
    qr_code_base64 = None
    payment_id = None # Útil para registrar ou verificar status depois

    if request.method == 'POST':
        valor_str = request.form.get('valor')
        descricao = request.form.get('descricao') or "Recarga via Pix"

        # 1. Validação do valor
        if not valor_str:
            flash("O valor da recarga é obrigatório.", "erro")
            return render_template("recarga.html", payment_pix_copy_paste=None, qr_code_base64=None)
        
        try:
            valor_float = float(valor_str)
            if valor_float <= 0:
                flash("O valor da recarga deve ser um número positivo.", "erro")
                return render_template("recarga.html", payment_pix_copy_paste=None, qr_code_base64=None)
        except ValueError:
            flash("Formato de valor inválido. Use números (ex: 10.50).", "erro")
            return render_template("recarga.html", payment_pix_copy_paste=None, qr_code_base64=None)

        try:
            sdk = mercadopago.SDK("APP_USR-3329527149542458-052717-28bb56f1a72c5d1af29f34065c847d48-283383607")
            payment_data = {
                "transaction_amount": valor_float,
                "description": descricao,
                "payment_method_id": "pix",
                "payer": {
                    # IMPORTANTE: Para testes, use um e-mail de teste válido do Mercado Pago.
                    # Ex: test_user_xxxxxxxx@testuser.com (substitua xxxxxxxx por números)
                    # Verifique a documentação do Mercado Pago sobre "Usuários de Teste".
                    "email": "test_user_12345678@testuser.com", 
                    "first_name": "Aluno",
                    "last_name": "Sistema"
                    # Considere adicionar CPF/CNPJ para pagamentos reais ou testes mais completos:
                    # "identification": {
                    # "type": "CPF",
                    # "number": "DOCUMENTO_VALIDO_AQUI" # Use um gerador de CPF para testes
                    # },
                }
                # "notification_url": url_for('webhook_mercado_pago', _external=True), # Essencial para produção
            }

            # 2. Criação do pagamento e verificação da resposta
            payment_response = sdk.payment().create(payment_data)
            
            # --- DEBUG DETALHADO ---
            print("----------------------------------------------------")
            print(f"[DEBUG MP Resposta Completa]: {payment_response}")
            # --- FIM DEBUG DETALHADO ---

            # Verifica se a chamada à API foi bem-sucedida (status HTTP 200 ou 201)
            if payment_response and payment_response.get("status") in [200, 201]:
                payment = payment_response.get("response")
                if payment:
                    payment_id = payment.get("id") # Bom para referência futura
                    print(f"[DEBUG MP Objeto Payment]: {payment}")
                    print(f"[DEBUG MP Status Pagamento]: {payment.get('status')}")
                    print(f"[DEBUG MP Status Detalhe]: {payment.get('status_detail')}")

                    point_of_interaction = payment.get("point_of_interaction")
                    if point_of_interaction and isinstance(point_of_interaction, dict):
                        transaction_data = point_of_interaction.get("transaction_data")
                        if transaction_data and isinstance(transaction_data, dict):
                            qr_code_base64 = transaction_data.get("qr_code_base64")
                            payment_pix_copy_paste = transaction_data.get("qr_code") # Este é o "Copia e Cola"

                            if qr_code_base64 and payment_pix_copy_paste:
                                flash("Pagamento Pix gerado com sucesso!", "sucesso")
                            else:
                                flash("Resposta da API recebida, mas dados do QR Code ou Pix Copia e Cola estão ausentes.", "erro")
                                print(f"[ERRO PIX INTERNO]: QR Code ou Copia e Cola ausentes. Transaction Data: {transaction_data}")
                        else:
                            flash("Erro ao processar dados da transação Pix na resposta da API.", "erro")
                            print(f"[ERRO PIX INTERNO]: 'transaction_data' não encontrado ou inválido em 'point_of_interaction'. POI: {point_of_interaction}")
                    else:
                        flash("Erro ao processar ponto de interação Pix na resposta da API.", "erro")
                        print(f"[ERRO PIX INTERNO]: 'point_of_interaction' não encontrado ou inválido. Payment: {payment}")
                else:
                    flash("Resposta da API bem-sucedida, mas sem conteúdo de pagamento ('response' ausente).", "erro")
                    print(f"[ERRO PIX INTERNO]: Chave 'response' ausente na resposta da API: {payment_response}")
            else:
                # A API retornou um erro ou status inesperado
                error_message = "Erro ao criar pagamento Pix junto ao Mercado Pago."
                if payment_response and payment_response.get("response") and payment_response["response"].get("message"):
                    error_message = payment_response["response"]["message"]
                elif payment_response and payment_response.get("message"):
                    error_message = payment_response.get("message")
                
                flash(f"Erro da API do Mercado Pago: {error_message}", "erro")
                print(f"[ERRO API MP]: {error_message} - Resposta Completa: {payment_response}")

        except mercadopago.exceptions.MPException as mp_error:
            flash(f"Erro na comunicação com o Mercado Pago: {mp_error}", "erro")
            print(f"[ERRO SDK MPException]: {mp_error}")
        except Exception as e:
            flash("Ocorreu um erro inesperado ao gerar o pagamento Pix. Tente novamente.", "erro")
            print(f"[ERRO PIX GERAL]: {e}")
            # Em desenvolvimento, pode ser útil relançar o erro para ver o traceback completo:
            # raise e 

    # Passa as variáveis para o template em todos os casos
    return render_template("recarga.html", 
                           payment_link=payment_pix_copy_paste, # Renomeado para clareza, este é o "Copia e Cola"
                           qr_code_base64=qr_code_base64)
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

def handler(request, context=None):
    return app(request.environ, start_response=context)


if __name__ == "__main__":
    from os import getenv
    port = int(getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
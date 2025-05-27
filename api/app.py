import os
from flask import Flask, request, jsonify, redirect, url_for, session, redirect, url_for, render_template, flash
from functools import wraps
import datetime
from supabase import create_client, Client
from dotenv import load_dotenv
from flask import send_from_directory
import bcrypt
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

from flask import flash  # já deve estar importado

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
            return redirect(url_for('inicio'))

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
    if acao == "pagamento":
        return render_template("pagamento.html", usuario=usuario_data)
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
@login_required() # Reutilizando seu decorador
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
import os
from flask import Flask, request, jsonify, redirect, url_for, session, redirect, url_for, render_template
from functools import wraps
import datetime
from supabase import create_client, Client
from dotenv import load_dotenv
from flask import send_from_directory
import bcrypt
app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'  # altere para algo seguro

load_dotenv()
# Recupera as variáveis de ambiente
url: str = os.getenv("SUPABASE_URL")
key: str = os.getenv("SUPABASE_KEY")

# Cria o cliente do Supabase
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
    error_message = None

    if request.method == 'POST':
        cpf_input = request.form.get('cpf')
        senha_input = request.form.get('senha')

        if not cpf_input or not senha_input:
            error_message = 'CPF e senha são obrigatórios.'
            return render_template('login.html', error_message=error_message)

        result = supabase.table("usuario").select("cpf, senha, aluno").eq("cpf", cpf_input).limit(1).execute()

        if result.data and len(result.data) == 1:
            usuario = result.data[0]
            stored_senha_hash_str = usuario['senha']
            is_aluno = usuario.get('aluno', True)

            # --- DEBUG PRINTS START ---
            print(f"DEBUG: Senha hash recuperada do Supabase (string): '{stored_senha_hash_str}'")
            print(f"DEBUG: Tipo da senha hash recuperada: {type(stored_senha_hash_str)}")
            print(f"DEBUG: Comprimento da senha hash recuperada: {len(stored_senha_hash_str) if stored_senha_hash_str else 'None'}")
            # --- DEBUG PRINTS END ---

            try:
                senha_hash_bytes = stored_senha_hash_str.encode('utf-8')
            except AttributeError:
                error_message = 'Erro interno: formato da senha inválido.'
                print("ERROR: stored_senha_hash_str não é uma string válida ou é None ao tentar encode.")
                return render_template('login.html', error_message=error_message)

            # --- DEBUG PRINTS START ---
            print(f"DEBUG: Senha hash após encode para bytes: '{senha_hash_bytes}'")
            print(f"DEBUG: Tipo da senha hash após encode: {type(senha_hash_bytes)}")
            # --- DEBUG PRINTS END ---

            if bcrypt.checkpw(senha_input.encode('utf-8'), senha_hash_bytes):
                session['logged_in'] = True
                session['usuario'] = cpf_input
                session['is_aluno'] = is_aluno
                
                if is_aluno:
                    return redirect(url_for('inicio'))
                else:
                    return redirect(url_for('admin_dashboard'))
            else:
                error_message = 'Senha incorreta.'
        else:
            error_message = 'Usuário não encontrado.'

    return render_template('login.html', error_message=error_message)

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    error_message = None
    success_message = None

    if request.method == 'POST':
        cpf = request.form.get('cpf')
        senha = request.form.get('senha')
        nome = request.form.get('nome')
        is_aluno = True 

        if not cpf or not senha or not nome:
            error_message = 'Todos os campos (CPF, Senha, Nome) são obrigatórios.'
            return render_template('cadastro.html', error_message=error_message)

        try:
            existing_user = supabase.table("usuario").select("cpf").eq("cpf", cpf).limit(1).execute()
            if existing_user.data and len(existing_user.data) > 0:
                error_message = f'O CPF {cpf} já está cadastrado.'
                return render_template('cadastro.html', error_message=error_message)

            senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # --- DEBUG PRINTS START ---
            print(f"DEBUG: Senha hash gerada para inserção: '{senha_hash}'")
            print(f"DEBUG: Tipo da senha hash gerada: {type(senha_hash)}")
            # --- DEBUG PRINTS END ---

            supabase.table("usuario").insert({
               "cpf": cpf,
               "senha": senha_hash,
               "nome": nome,
               "saldo": 0,
               "aluno": is_aluno
            }).execute()

            session['logged_in'] = True
            session['usuario'] = cpf
            session['is_aluno'] = is_aluno 
            success_message = 'Cadastro realizado com sucesso! Redirecionando para a página inicial...'
            return redirect(url_for('inicio')) 
        except Exception as e:
            print(f"ERROR - Cadastro: Erro ao cadastrar usuário: {e}")
            error_message = 'Ocorreu um erro ao cadastrar. Tente novamente.'

    return render_template('cadastro.html', error_message=error_message, success_message=success_message)

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
        result = supabase.table("usuario").select("nome, cpf, saldo").eq("cpf", cpf_usuario).limit(1).execute()

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

@app.route('/cadastroaluno', methods=['GET', 'POST'])
@admin_required()
def cadastro_aluno():
    error_message = None
    success_message = None

    if request.method == 'POST':
        cpf = request.form.get('cpf')
        senha = request.form.get('senha')
        nome = request.form.get('nome')
        is_aluno = True

        if not cpf or not senha or not nome:
            error_message = 'Todos os campos (CPF, Senha, Nome) são obrigatórios.'
            return render_template('cadastro_aluno.html', error_message=error_message)

        try:
            existing_user = supabase.table("usuario").select("cpf").eq("cpf", cpf).limit(1).execute()
            if existing_user.data and len(existing_user.data) > 0:
                error_message = f'O CPF {cpf} já está cadastrado.'
                return render_template('cadastro_aluno.html', error_message=error_message)

            senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            supabase.table("usuario").insert({
               "cpf": cpf,
               "senha": senha_hash,
               "nome": nome,
               "saldo": 0,
               "aluno": is_aluno
            }).execute()

            success_message = f'Aluno {nome} ({cpf}) cadastrado com sucesso!'
        except Exception as e:
            print(f"ERROR - Cadastro Aluno: Erro ao cadastrar aluno: {e}")
            error_message = 'Ocorreu um erro ao cadastrar o aluno. Tente novamente.'
    
    return render_template('cadastro_aluno.html', error_message=error_message, success_message=success_message)

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


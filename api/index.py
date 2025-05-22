import os
from flask import Flask, request, jsonify, redirect, url_for, session, redirect, url_for, render_template
from functools import wraps
import datetime
from supabase import create_client, Client
from dotenv import load_dotenv
import uuid

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'  # altere para algo seguro

load_dotenv()
# Recupera as variáveis de ambiente
url: str = os.getenv("SUPABASE_URL")
key: str = os.getenv("SUPABASE_KEY")

# Cria o cliente do Supabase
supabase: Client = create_client(url, key)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        cpf_input = request.form['cpf']
        senha_input = request.form['senha']

        # Tenta buscar o usuário
        result = supabase.table("tb_usuario").select("*").eq("cpf", cpf_input).single().execute()

        if result.data:
            usuario = result.data
            if usuario['senha'] == senha_input:
                session['logged_in'] = True
                session['usuario'] = cpf_input
                return redirect(url_for('consulta'))
            else:
                session['error_message'] = 'Senha incorreta.'
                return redirect(url_for('login'))
        else:
            # Usuário não encontrado — redireciona para cadastro
            session['pre_cadastro'] = {'cpf': cpf_input, 'senha': senha_input}
            return redirect(url_for('cadastro'))

    error_message = session.get('error_message', None)
    return render_template('login.html', error_message=error_message)


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    pre_cadastro = session.get('pre_cadastro', None)

    if request.method == 'POST':
        nome = request.form['nome']
        ra = request.form['ra']
        cpf = pre_cadastro['cpf']
        senha = pre_cadastro['senha']

        # Verifica se RA já existe
        existing = supabase.table("tb_aluno").select("id").eq("ra", ra).execute()
        if existing.data:
            erro = f"O RA {ra} já está cadastrado."
            return render_template('cadastro.html', result='erro', erro=erro)

        # Cria aluno
        aluno_response = supabase.table("tb_aluno").insert({
            "id": str(uuid.uuid4()),
            "nome": nome,
            "ra": ra
        }).execute()

        aluno_id = aluno_response.data[0]['id']

        # Cria usuário vinculado ao aluno
        supabase.table("tb_usuario").insert({
            "id": str(uuid.uuid4()),
            "cpf": cpf,
            "senha": senha,
            "id_aluno": aluno_id
        }).execute()

        session['logged_in'] = True
        session['usuario'] = cpf
        return redirect(url_for('home'))

    return render_template('cadastro.html', pre_cadastro=pre_cadastro)
import os
from flask import Flask, request, jsonify, redirect, url_for, session, redirect, url_for, render_template
from functools import wraps
import datetime
from supabase import create_client, Client
from dotenv import load_dotenv
import uuid

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'  # altere para algo seguro

load_dotenv()
# Recupera as variáveis de ambiente
url: str = os.getenv("SUPABASE_URL")
key: str = os.getenv("SUPABASE_KEY")

# Cria o cliente do Supabase
supabase: Client = create_client(url, key)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        cpf_input = request.form['cpf']
        senha_input = request.form['senha']

        # Tenta buscar o usuário
        result = supabase.table("tb_usuario").select("*").eq("cpf", cpf_input).single().execute()

        if result.data:
            usuario = result.data
            if usuario['senha'] == senha_input:
                session['logged_in'] = True
                session['usuario'] = cpf_input
                return redirect(url_for('consulta'))
            else:
                session['error_message'] = 'Senha incorreta.'
                return redirect(url_for('login'))
        else:
            # Usuário não encontrado — redireciona para cadastro
            session['pre_cadastro'] = {'cpf': cpf_input, 'senha': senha_input}
            return redirect(url_for('cadastro'))

    error_message = session.get('error_message', None)
    return render_template('login.html', error_message=error_message)


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    pre_cadastro = session.get('pre_cadastro', None)

    if request.method == 'POST':
        nome = request.form['nome']
        ra = request.form['ra']
        cpf = pre_cadastro['cpf']
        senha = pre_cadastro['senha']

        # Verifica se RA já existe
        existing = supabase.table("tb_aluno").select("id").eq("ra", ra).execute()
        if existing.data:
            erro = f"O RA {ra} já está cadastrado."
            return render_template('cadastro.html', result='erro', erro=erro)

        # Cria aluno
        aluno_response = supabase.table("tb_aluno").insert({
            "id": str(uuid.uuid4()),
            "nome": nome,
            "ra": ra
        }).execute()

        aluno_id = aluno_response.data[0]['id']

        # Cria usuário vinculado ao aluno
        supabase.table("tb_usuario").insert({
            "id": str(uuid.uuid4()),
            "cpf": cpf,
            "senha": senha,
            "id_aluno": aluno_id
        }).execute()

        session['logged_in'] = True
        session['usuario'] = cpf
        return redirect(url_for('home'))

    return render_template('cadastro.html', pre_cadastro=pre_cadastro)
@app.route('/')
def home():
    return render_template("login.html")

# importante: para Vercel funcionar com Flask, você precisa isso:
def handler(request, context=None):
    return app(request.environ, start_response=context)


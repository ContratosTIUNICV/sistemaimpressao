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
    return send_from_directory('templates/imagens', filename)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        cpf_input = request.form['cpf']
        senha_input = request.form['senha']

        # Busca o usuário sem usar .single(), para evitar erro se não encontrar
        result = supabase.table("usuario").select("*").eq("cpf", cpf_input).execute()

        if result.data and len(result.data) == 1:
            usuario = result.data[0]
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
        cpf = pre_cadastro['cpf']
        senha = pre_cadastro['senha']
        nome = request.form['nome']

        senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        supabase.table("usuario").insert({
         "cpf": cpf,
        "senha": senha_hash,
        "nome": nome  # se a tabela tiver coluna nome
        }).execute()

        session['logged_in'] = True
        session['usuario'] = cpf
        return redirect(url_for('home'))

    return render_template('cadastro.html', pre_cadastro=pre_cadastro)
@app.route('/')
def home():
    return redirect(url_for('login'))
@app.route('/logout')
def logout():
    session.clear()  # limpa a sessão
    return redirect(url_for('login'))
def handler(request, context=None):
    return app(request.environ, start_response=context)

if __name__ == '__main__':
    app.run(debug=True)
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
            # A lógica aqui considera que se 'is_membro' for Falso, o usuário é um admin.
            if session.get('is_membro') == True:
                return redirect(url_for('inicio'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        codigo_membro_input = request.form.get('codigo_membro')
        senha_input = request.form.get('senha')

        if not codigo_membro_input or not senha_input:
            flash('Código de membro e senha são obrigatórios.', 'erro')
            return render_template('login.html')

        # Busca pelo novo campo 'codigo_membro' e pelo campo 'membro'
        result = supabase.table("usuario").select("id, codigo_membro, senha, membro, nome").eq("codigo_membro", codigo_membro_input).limit(1).execute()

        if result.data and len(result.data) == 1:
            usuario = result.data[0]
            stored_senha_hash_str = usuario['senha']
            # O campo 'membro' (booleano) define se é um membro comum ou admin
            is_membro = usuario.get('membro', True)
            nome = usuario.get('nome', 'usuário')

            try:
                senha_hash_bytes = stored_senha_hash_str.encode('utf-8')
            except AttributeError:
                flash('Erro interno: formato da senha inválido.', 'erro')
                return render_template('login.html')

            if bcrypt.checkpw(senha_input.encode('utf-8'), senha_hash_bytes):
                session['logged_in'] = True
                session['usuario_id'] = usuario['id'] # Armazena o ID principal
                session['usuario_codigo'] = codigo_membro_input # Mantém o código para exibição/uso
                session['is_membro'] = is_membro
                if is_membro:
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
        codigo_membro = request.form.get('codigo_membro')
        email = request.form.get('email')
        senha = request.form.get('senha')
        nome = request.form.get('nome')
        is_membro = True  # Novos cadastros são sempre de membros comuns

        if not codigo_membro or not senha or not nome:
            flash('Todos os campos (Código de Membro, Senha, Nome) são obrigatórios.', 'erro')
            return render_template('cadastro.html')

        try:
            existing_user = supabase.table("usuario").select("codigo_membro").eq("codigo_membro", codigo_membro).limit(1).execute()
            if existing_user.data:
                flash(f'O código {codigo_membro} já está cadastrado.', 'erro')
                return render_template('cadastro.html')

            senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Insere usando os novos nomes de coluna. Removido o campo "saldo".
            supabase.table("usuario").insert({
                "codigo_membro": codigo_membro,
                "senha": senha_hash,
                "nome": nome,
                "email": email,
                "membro": is_membro
            }).execute()
            flash(f'Seja bem-vindo, {nome}!', 'sucesso')
            return redirect(url_for('login')) # Redireciona para o login após o cadastro
        except Exception as e:
            print(f"ERRO: {e}")
            flash('Ocorreu um erro ao cadastrar. Tente novamente.', 'erro')
    return render_template('cadastro.html')

@app.route('/')
def home():
    if session.get('logged_in'):
        if session.get('is_membro') == False:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('inicio'))
    return redirect(url_for('login'))

@app.route('/inicio')
@login_required()
def inicio():
    codigo_membro_usuario = session.get('usuario_codigo')
    if not codigo_membro_usuario:
        session.clear()
        return redirect(url_for('login'))

    usuario_data = None
    eventos = []
    
    try:
        # Busca dados do usuário (sem o saldo)
        result_usuario = supabase.table("usuario").select("nome, codigo_membro").eq("codigo_membro", codigo_membro_usuario).limit(1).execute()
        if result_usuario.data and len(result_usuario.data) == 1:
            usuario_data = result_usuario.data[0]
        else:
            session.clear()
            return redirect(url_for('login'))

        # Busca eventos futuros
        hoje = datetime.datetime.now().isoformat()
        result_eventos = supabase.table("eventos").select("*").gte("data_evento", hoje).order("data_evento", desc=False).execute()
        if result_eventos.data:
            eventos = result_eventos.data

    except Exception as e:
        print(f"ERROR - Inicio: Erro ao buscar dados: {e}")
        flash('Erro ao carregar a página inicial.', 'erro')

    return render_template('inicio.html', usuario=usuario_data, eventos=eventos)

@app.route('/admin')
@admin_required()
def admin_dashboard():
    return render_template('admin.html')

@app.route('/consultamembros')
@admin_required()
def consulta_membros():
    membros = []
    try:
  
        result = supabase.table("usuario").select("codigo_membro, nome").eq("membro", True).order("nome").execute()
        if result.data:
            membros = result.data
    except Exception as e:
        print(f"ERROR - Consulta Membros: {e}")
    return render_template('consulta_aluno.html', alunos=membros) # 


@app.route('/eventos/criar', methods=['GET', 'POST'])
@admin_required()
def criar_evento():
    if request.method == 'POST':
        nome_evento = request.form.get('nome_evento')
        data_evento = request.form.get('data_evento')
        descricao = request.form.get('descricao')
        local = request.form.get('local')

        if not nome_evento or not data_evento or not local:
            flash('Nome, data e local do evento são obrigatórios.', 'erro')
            return render_template('criarevento.html')

        try:
            supabase.table("eventos").insert({
                "nome_evento": nome_evento,
                "data_evento": data_evento,
                "descricao": descricao,
                "local": local
            }).execute()
            flash('Evento criado com sucesso!', 'sucesso')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            print(f"ERRO ao criar evento: {e}")
            flash('Ocorreu um erro ao criar o evento.', 'erro')

    return render_template('criarevento.html')

@app.route('/eventos/<int:id_evento>/presenca', methods=['GET', 'POST'])
@admin_required()
def presenca_evento(id_evento):
    try:
        evento = supabase.table("eventos").select("*").eq("id", id_evento).single().execute().data
        if not evento:
            flash("Evento não encontrado.", "erro")
            return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash(f"Erro ao buscar evento: {e}", "erro")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        codigo_membro = request.form.get('codigo_membro')

        try:
            membro = supabase.table("usuario").select("id, nome").eq("codigo_membro", codigo_membro).single().execute().data
            if not membro:
                flash(f'Membro com código {codigo_membro} não encontrado.', 'erro')
                return render_template('presencaevento.html', evento=evento)

            ja_registrado = supabase.table("presencas").select("id").eq("id_evento", id_evento).eq("id_usuario", membro['id']).execute().data
            if ja_registrado:
                flash(f'{membro["nome"]} já teve sua presença registrada neste evento.', 'info')
            else:
                supabase.table("presencas").insert({
                    "id_evento": id_evento,
                    "id_usuario": membro['id']
                }).execute()
                flash(f'Presença de {membro["nome"]} registrada com sucesso!', 'sucesso')
        
        except Exception as e:
            print(f"ERRO ao registrar presença: {e}")
            flash('Ocorreu um erro ao registrar a presença.', 'erro')

    return render_template('presencaevento.html', evento=evento)

#
# --- FIM DAS NOVAS ROTAS DE EVENTOS ---
#

@app.route('/perfil/editar', methods=['GET', 'POST'], endpoint='editar_perfil')
@login_required()
def editar_perfil():
    codigo_membro_logado = session.get('usuario_codigo')
    if not codigo_membro_logado:
        flash('Erro: Sessão inválida. Faça login novamente.', 'error')
        return redirect(url_for('login'))

    try:
        result = supabase.table("usuario").select("nome, codigo_membro").eq("codigo_membro", codigo_membro_logado).limit(1).execute()
        if not result.data:
            flash('Usuário não encontrado.', 'error')
            return redirect(url_for('inicio'))
        usuario_atual = result.data[0]
    except Exception as e:
        print(f"ERROR - Editar Perfil (GET user data): {e}")
        flash('Erro ao carregar dados do perfil.', 'error')
        return redirect(url_for('inicio'))

    if request.method == 'POST':
        novo_nome = request.form.get('nome')
        nova_senha = request.form.get('nova_senha')
        confirmar_nova_senha = request.form.get('confirmar_nova_senha')
        dados_para_atualizar = {}
        houve_alteracao = False

        if novo_nome and novo_nome != usuario_atual.get('nome'):
            dados_para_atualizar['nome'] = novo_nome
            houve_alteracao = True

        if nova_senha:
            if len(nova_senha) < 4:
                flash('A nova senha deve ter pelo menos 4 caracteres.', 'error')
                return render_template('editar_perfil.html', usuario=usuario_atual)
            if nova_senha != confirmar_nova_senha:
                flash('As senhas não coincidem.', 'error')
                return render_template('editar_perfil.html', usuario=usuario_atual)
            
            senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            dados_para_atualizar['senha'] = senha_hash
            houve_alteracao = True

        if houve_alteracao:
            try:
                supabase.table("usuario").update(dados_para_atualizar).eq("codigo_membro", codigo_membro_logado).execute()
                flash('Perfil atualizado com sucesso!', 'success')
            except Exception as e:
                print(f"ERROR - Editar Perfil (Supabase Update): {e}")
                flash('Erro ao atualizar o perfil no banco de dados.', 'error')
        else:
            flash('Nenhuma alteração foi detectada.', 'info')
        
        return redirect(url_for('inicio'))

    return render_template('editar_perfil.html', usuario=usuario_atual)

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da sua conta.', 'sucesso')
    return redirect(url_for('login'))

# Função para Vercel (se estiver usando)
def handler(request, context=None):
    return app(request.environ, start_response=context)

if __name__ == "__main__":
    from os import getenv
    port = int(getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
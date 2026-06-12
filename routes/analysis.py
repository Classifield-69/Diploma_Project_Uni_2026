"""
Blueprint за ML анализ на ревюта.

-> Анализ на ревюта с LSTM и BiLSTM модели (POST /api/movies/<id>/analyze)
-> Endpoint-ът е само за администратори (admin_required)

Какво ще прави Blueprint-а:
-> Анализират се САМО ревюта, при които поне една от колоните
  lstm_prediction или bilstm_prediction е NULL
-> Вече анализирани ревюта не се анализират повторно
-> Двата модела се пускат заедно
"""

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from mysql.connector import Error

from database.connection import get_connection
from routes.auth import admin_required
from ml.inference import predict


# Blueprint
analysis_bp = Blueprint("analysis", __name__, url_prefix="/api")


# Endpoint: POST /api/movies/<movie_id>/analyze
@analysis_bp.route("/movies/<int:movie_id>/analyze", methods=["POST"])
@jwt_required()
@admin_required
def analyze_movie_reviews(movie_id):
    """
    Пуска ML анализ върху ревютата на даден филм.

    Защитен endpoint:
    - Изисква валиден JWT (@jwt_required)
    - Изисква role = 'admin' (@admin_required)

    Връща:
    - 200: Успешен анализ, със статистика колко са анализирани
    - 401: Липсва или невалиден JWT
    - 403: User не е admin
    - 404: Филмът не съществува
    - 500: Сървърна грешка (база, модели и т.н.)
    """
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        # Проверяваме дали филмът съществува -----
        cursor.execute("SELECT id, title FROM movies WHERE id = %s", (movie_id,))
        movie = cursor.fetchone()

        if movie is None:
            return jsonify({
                "status": "error",
                "message": f"Филм с id={movie_id} не съществува"
            }), 404

        # Проверяваме колко ревюта има за дадения филм -----
        cursor.execute(
            "SELECT COUNT(*) AS total FROM reviews WHERE movie_id = %s",
            (movie_id,)
        )
        total_reviews = cursor.fetchone()["total"]

        # Търсим неанализирани ревюта
        cursor.execute(
            """
            SELECT id, text
            FROM reviews
            WHERE movie_id = %s
              AND (lstm_prediction IS NULL OR bilstm_prediction IS NULL)
            """,
            (movie_id,)
        )
        unanalyzed = cursor.fetchall()

        # Ако всички ревюта са анализирани, излиза
        if not unanalyzed:
            cursor.close()
            connection.close()
            return jsonify({
                "status": "ok",
                "message": "Всички ревюта вече са анализирани",
                "movie_id": movie_id,
                "movie_title": movie["title"],
                "total_reviews": total_reviews,
                "analyzed_count": 0,
                "newly_analyzed_count": 0
            }), 200

        # ML предсказание 
        # Взимаме само текстовете и id-тата в отделни списъци
        review_ids = [r["id"] for r in unanalyzed]
        review_texts = [r["text"] for r in unanalyzed]

        # !!! При първи predict() след startup на сървъра, тук ще има ~5-10 сек забавяне (зареждане на TF + двата .keras файла).
        predictions = predict(review_texts)

        # UPDATE на базата с резултатите
        update_query = """
            UPDATE reviews
            SET lstm_prediction = %s, bilstm_prediction = %s
            WHERE id = %s
        """
        update_params = [
            (pred["lstm_rating"], pred["bilstm_rating"], rid)
            for rid, pred in zip(review_ids, predictions)
        ]

        # Нов cursor без dictionary=True за UPDATE-и
        cursor.close()
        cursor = connection.cursor()
        # Използваме executemany, защото прави една заявка със X стойности
        cursor.executemany(update_query, update_params)
        connection.commit()

        newly_analyzed = cursor.rowcount
        cursor.close()
        connection.close()

        # Връщаме статистика
        return jsonify({
            "status": "ok",
            "message": f"Анализирани са {newly_analyzed} ревюта",
            "movie_id": movie_id,
            "movie_title": movie["title"],
            "total_reviews": total_reviews,
            "newly_analyzed_count": newly_analyzed
        }), 200

    except Error as e:
        # MySQL грешка
        if cursor:
            cursor.close()
        if connection:
            connection.close()
        return jsonify({
            "status": "error",
            "message": "Грешка при достъп до базата",
            "details": str(e)
        }), 500

    except Exception as e:
        # ML или друга неочаквана грешка
        if cursor:
            cursor.close()
        if connection:
            connection.close()
        return jsonify({
            "status": "error",
            "message": "Грешка при ML анализ",
            "details": str(e)
        }), 500

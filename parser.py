import json
from dojo.models import Finding
import logging

logger = logging.getLogger(__name__)

class PtblackboxsarifParser(object):
    """
    Парсер для SARIF отчетов PT Black Box
    """

    def get_scan_types(self):
        return ["PT Black Box SARIF"]

    def get_label_for_scan_types(self, scan_type):
        return "PT Black Box SARIF"

    def get_description_for_scan_types(self, scan_type):
        return "Парсер для SARIF отчетов PT Black Box."

    def get_findings(self, file, test):
        findings = []
        try:
            data = json.load(file)

            # Создаем словарь правил
            rules_dict = {rule.get('id'): rule for rule in data['runs'][0]['tool']['driver']['rules']}

            # Обрабатываем результаты
            for result in data['runs'][0]['results']:
                rule_id = result.get('ruleId')
                rule = rules_dict.get(rule_id, {})

                severity_level = rule.get('defaultConfiguration', {}).get('level', 'note').lower()
                severity = self.map_severity(severity_level)

                description = rule.get('fullDescription', {}).get('text', 'Описание отсутствует.')
                title = rule.get('name', 'Без названия')

                # Извлечение местоположения
                locations = result.get('locations', [])
                if locations:
                    physical_location = locations[0].get('physicalLocation', {})
                    artifact_location = physical_location.get('artifactLocation', {})
                    file_path = artifact_location.get('uri', None)
                    region = physical_location.get('region', {})
                    line = region.get('startLine', None)
                    if line is not None:
                        try:
                            line = int(line)
                        except ValueError:
                            line = None
                else:
                    file_path = None
                    line = None

                # Создание объекта Finding
                finding = Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    file_path=file_path,
                    line=line,  # Изменено с line_number на line
                    cve=rule_id,  # Используем ruleId как идентификатор
                    test=test
                )
                findings.append(finding)

                logger.debug(f"Добавлена уязвимость: {title} с серьезностью {severity}")

            logger.info(f"Всего найдено уязвимостей: {len(findings)}")

        except Exception as e:
            logger.error(f"Ошибка при парсинге SARIF отчета PT Black Box: {e}")
            raise  # Повторно выбрасываем исключение

        return findings

    def map_severity(self, severity):
        """
        Определяем уровень серьезности.
        """
        severity_mapping = {
            'error': 'High',
            'warning': 'Medium',
            'note': 'Low',
            'informational': 'Info',
            'none': 'Info'
        }
        return severity_mapping.get(severity, 'Medium')

var mdb = require('../mdb');

exports.postStatements = function (req, res) {
    if (!req.user) {
        res.status(500).send('');
    } else {
        req.body.forEach(function (data) {
            var statement = {};

            statement.actor = req.user._id;

            if ('verb' in data && 'id' in data.verb) {
                statement.verbId = data.verb.id;
            }

            if ('object' in data) {
                statement.object = data.object;
            }

            if ('result' in data) {
                statement.result = data.result;
            }

            statement.context = {};

            if ('timestamp' in data) {
                statement.timestamp = data.timestamp;
            }

            statement.stored = new Date();

            statement.authorty = {};
            statement.version = '1.0.0';

            statement.attachments = [];

            mdb.LearningRecord.create(statement, function (err) {
                return;
            });
        });

        res.status(200).json({ ok: true });
    }
};

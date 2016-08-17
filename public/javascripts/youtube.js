var $ = require('jquery');
var _ = require('underscore');
var TinCan = require('./tincan');

function onPlayerStateChange(event) {
    if (event.data == YT.PlayerState.PLAYING) {
        var url = event.target.getVideoUrl();
        url = url.toString().replace(/feature=player_embedded&/, '');

        var title = event.target.getVideoData().title;

        TinCan.experienceVideo(url, title);
    }
}

var videosToConstruct = [];

var player = {
    playVideo: function (container, videoId) {
        if (typeof YT == 'undefined' || typeof YT.Player == 'undefined') {
            videosToConstruct.push([container, videoId]);

            $.getScript('//www.youtube.com/iframe_api');
        } else {
            player.loadPlayer(container, videoId);
        }
    },

    loadPlayer: function (container, videoId) {
        var player = new YT.Player(container, {
            videoId: videoId,
            width: 640,
            height: 360,
            // For a list of all parameters, see:
            // https://developers.google.com/youtube/player_parameters
            playerVars: {
                autoplay: 0,
                controls: 1,
                modestbranding: 1,
                rel: 0,
                showinfo: 0
            },
            events: {
                'onStateChange': onPlayerStateChange
            }
        });
    }
};

window.onYouTubeIframeAPIReady = _.once(function () {
    _.each(videosToConstruct, function (video) {
        player.loadPlayer(video[0], video[1]);
    });
});

$(function () {
    $('.youtube-player').each(function () {
        var div = $(this);
        div.uniqueId();
        var id = div.attr('id');

        var url = div.attr('data-youtube');

        if (url.match(/watch\?v=/)) {
            url = url.replace(/.*watch\?v=/, '');
        }

        player.playVideo(id, url);
    });
});

module.exports = player;

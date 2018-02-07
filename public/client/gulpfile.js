/*eslint strict: 0, */
/*global require*/

var paths = require('./paths.json');
var gulp = require('gulp');
var concat = require('gulp-concat');
var uglify = require('gulp-uglify');
var sass = require('gulp-sass');
var babel = require('gulp-babel');
var changed = require('gulp-changed');
var sourcemaps = require('gulp-sourcemaps');
var plumber = require('gulp-plumber');
var ngAnnotate = require('gulp-ng-annotate');
var gulpif = require('gulp-if');
var cleanCSS = require('gulp-clean-css');
var inject = require('gulp-inject');
var lazypipe = require('lazypipe');
var browserSync = require('browser-sync');
var gutil = require('gulp-util');
var eslint = require('gulp-eslint');
var runSequence = require('run-sequence');
var argv = require('yargs').argv;

paths.client = '.';
paths.node = 'node_modules';

paths.app = paths.client + '/app';
paths.destination = paths.client + '/build';
paths.angularScripts = [
  paths.node + '/deep-diff/index.js',
  paths.node + '/uri-templates/uri-templates.js',
  paths.node + '/angular/angular.js',
  paths.node + '/angular-aria/angular-aria.js',
  paths.node + '/angular-sanitize/angular-sanitize.js',
  paths.node + '/angular-animate/angular-animate.js',
  paths.node + '/angular-resource/angular-resource.min.js',
  paths.node + '/angular-translate/dist/angular-translate.min.js',
  paths.node + '/angular-i18n/angular-locale_pt-br.js',
  paths.node + '/angular-input-masks/releases/angular-input-masks-standalone.min.js',
  paths.node + '/angular1-text-mask/dist/angular1TextMask.js',
  paths.node + '/angular-ui-router/release/angular-ui-router.min.js',
  paths.node + '/angular-material/angular-material.js',
  paths.node + '/angular-material-data-table/dist/md-data-table.min.js',
  paths.node + '/angular-model-factory/dist/angular-model-factory.js',
  paths.node + '/angular-file-upload/dist/angular-file-upload.js',
  paths.node + '/ng-material-datetimepicker/dist/angular-material-datetimepicker.min.js',
  paths.node + '/ng-prodeb/dist/ng-prodeb.js',
  paths.node + '/angular-messages/angular-messages.min.js',
  paths.node + '/jqwidgets-framework/jqwidgets/jqxcore.js',
  paths.node + '/jqwidgets-framework/jqwidgets/jqxdata.js',
  paths.node + '/jqwidgets-framework/jqwidgets/jqxsortable.js',
  paths.node + '/jqwidgets-framework/jqwidgets/jqxkanban.js',
  paths.node + '/jqwidgets-framework/jqwidgets/jqxangular.js',
  'bower_components/angular-route/angular-route.js',
  paths.node + '/angular-ui-mask/dist/mask.js',
  paths.node + '/please-wait/build/please-wait.min.js'
];
//Add minifieds files.
paths.vendorsScripts = [
  paths.node + '/alasql/dist/alasql.js',
  paths.node + '/xlsx/dist/xlsx.core.min.js',
  paths.node + '/lodash/lodash.min.js',
  paths.node + '/moment/min/moment.min.js',
  paths.node + '/moment/min/locales.min.js'
];
paths.scripts = [
  paths.app + '/app.js',
  paths.app + '/app.*.js',
  paths.app + '/**/*.js'
];
paths.styles = [
  paths.node   + '/ng-prodeb/dist/ng-prodeb.css',
  paths.node   + '/angular-material-data-table/dist/md-data-table.min.css',
  paths.node   + '/ng-material-datetimepicker/dist/material-datetimepicker.min.css',
  paths.node   + '/jqwidgets-framework/jqwidgets/styles/jqx.base.css',
  paths.node   + '/jqwidgets-framework/jqwidgets/styles/jqx.classic.css',
  paths.node   + '/jqwidgets-framework/jqwidgets/styles/jqx.fresh.css',
  paths.node   + '/jqwidgets-framework/jqwidgets/styles/jqx.glacier.css',
  paths.node   + '/jqwidgets-framework/jqwidgets/styles/jqx.light.css', //
  paths.node   + '/jqwidgets-framework/jqwidgets/styles/jqx.metro.css',
  paths.node   + '/jqwidgets-framework/jqwidgets/styles/jqx.mobile.css', //
  paths.node   + '/jqwidgets-framework/jqwidgets/styles/jqx.office.css',
  paths.node   + '/jqwidgets-framework/jqwidgets/styles/jqx.summer.css',
  paths.node   + '/please-wait/build/please-wait.css',
  paths.client  + '/styles/app.scss'
];

var filesNames = {
  vendors: (argv.production) ? 'vendors.min.js' : 'vendors.js',
  angular: (argv.production) ? 'angular-with-plugins.min.js' : 'angular-with-plugins.js',
  application: (argv.production) ? 'application.min.js' : 'application.js'
}

var globalRandom = Math.random().toString(36).substr(2, 15);

var minifierCSSChannel = lazypipe()
  .pipe(cleanCSS);

function buildScripts(files, fileName) {
  var stream = gulp.src(files).pipe(plumber());

  if (argv.production) {
    stream = stream.pipe(concat(fileName))
      .pipe(uglify());
  } else {
    stream = stream.pipe(sourcemaps.init())
      .pipe(changed(paths.destination))
      .pipe(concat(fileName))
      .pipe(sourcemaps.write())
  }

  return stream.pipe(gulp.dest(paths.destination));
}

function scriptsVendors() {
  return buildScripts(paths.vendorsScripts, filesNames.vendors);
};

function scriptsAngular() {
  return buildScripts(paths.angularScripts, filesNames.angular);
};

function scriptsApplication() {
  var stream = gulp.src(paths.scripts)
    .pipe(plumber())
    .pipe(gulpif(!argv.production, sourcemaps.init()))
    .pipe(gulpif(!argv.production, changed(paths.destination)))
    .pipe(babel({
      presets: ['es2015']
    }))
    .pipe(concat(filesNames.application))
    .pipe(ngAnnotate({
      add: true
    }))
    .pipe(gulp.dest(paths.destination))
    .pipe(gulpif(argv.production, uglify()))
    .pipe(gulpif(!argv.production, sourcemaps.write()))
    .pipe(gulp.dest(paths.destination));

  return stream;
};

function styles() {
  return gulp.src(paths.styles)
    .pipe(plumber())
    .pipe(gulpif(!argv.production, sourcemaps.init()))
    .pipe(changed(paths.destination))
    .pipe(sass())
    .pipe(concat('application.css'))
    .pipe(gulpif(argv.production, minifierCSSChannel()))
    .pipe(gulpif(!argv.production, sourcemaps.write()))
    .pipe(gulp.dest(paths.destination));
};

function injectFiles() {
  var random = Math.random().toString(36).substr(2, 15);

  gulp.src(paths.client + '/index.html')
    .pipe(inject(gulp.src([
      paths.destination + '/' + filesNames.application
    ], { read: false }), {
      starttag: '<!-- inject:application:script -->',
      endtag: '<!-- end:inject:application:script -->',
      ignorePath: 'public',
      addRootSlash: false,
      addPrefix: paths.serverClientPath,
      addSuffix: '?version=' + random
    }))
    .pipe(inject(gulp.src([
      paths.destination + '/*.css'
    ], { read: false }), {
      starttag: '<!-- inject:all:css -->',
      endtag: '<!-- end:inject:all:css -->',
      ignorePath: 'public',
      addRootSlash: false,
      addPrefix: paths.serverClientPath,
      addSuffix: '?version=' + globalRandom
    }))
    .pipe(inject(gulp.src([
      paths.destination + '/' + filesNames.vendors,
      paths.destination + '/' + filesNames.angular,
      '!' + paths.destination + '/' + filesNames.application
    ], { read: false }), {
      starttag: '<!-- inject:vendors:script -->',
      endtag: '<!-- end:inject:vendors:script -->',
      ignorePath: 'public',
      addRootSlash: false,
      addPrefix: paths.serverClientPath,
      addSuffix: '?version=' + globalRandom
    }))
    .pipe(gulp.dest(paths.client));
}

gulp.task('scriptsVendors', scriptsVendors);
gulp.task('scriptsAngular', scriptsAngular);
gulp.task('scriptsApplication', scriptsApplication);
gulp.task('styles', styles);
gulp.task('injectFiles', injectFiles);

/**
 * Task to sync the browser with changes in the
 * source code.
 */
gulp.task('browser-sync', function() {
  if (argv.sync && !argv.production) {
    browserSync({
      port: 5005
    });
  }
});

// Rerun the task when a file changes
gulp.task('watch', function() {
  if (!argv.production) {
    gulp.watch(paths.scripts, ['scriptsApplication', 'injectFiles']).on('change', browserSync.reload);
    gulp.watch(paths.app + '/**/*.html').on('change', browserSync.reload);
    gulp.watch(paths.styles, ['styles']).on('change', browserSync.reload);
  }
});

/**
 * Build js files and inject into index.html
 */
gulp.task('build', function() {
  runSequence(['styles', 'scriptsVendors', 'scriptsAngular', 'scriptsApplication'], 'injectFiles');
});

/**
 * Check all .js files using eslint
 * --fix can be passed to fix possible problems
 */
gulp.task('check', function() {
  gutil.log(gutil.colors.blue('Executando a analise do eslint'));

  return gulp.src([paths.app + '/*.js', paths.app + '/**/*.js'])
    .pipe(eslint({
      fix: ((argv.fix) ? true : false)
    }))
    .pipe(eslint.format());
});

gulp.task('default', ['browser-sync', 'watch', 'build'], function() {});
gulp.task('minifier', ['build-production'], function() {});

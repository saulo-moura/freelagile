/*eslint strict: 0, */
/*global require*/

var gulp = require('gulp');
var concat = require('gulp-concat');
var babel = require('gulp-babel');
var uglify = require('gulp-uglify');
var rename = require('gulp-rename');
var changed = require('gulp-changed');
var sourcemaps = require('gulp-sourcemaps');
var plumber = require('gulp-plumber');
var shell = require('gulp-shell')
var ngAnnotate = require('gulp-ng-annotate');
var cleanCSS = require('gulp-clean-css');
var sass = require('gulp-sass');
var argv = require('yargs').argv;

var names = {
  lib: 'ng-prodeb'
}

var paths = {
  node: 'node_modules',
  allScripts: 'src/**/*.js',
  destination: 'dist',
  scripts: [
    'src/app.js',
    'src/app.config.js',
    'src/app.external.js',
    'src/**/*.js'
  ],
  styles: [
    'src/styles/*.scss',
    'src/styles/*.css'
  ]
};

paths.stylesVendors = [
  paths.node + '/angular-material/angular-material.css',
  paths.node + '/angular-material-data-table/dist/md-data-table.css',
  paths.node + '/ng-material-datetimepicker/dist/material-datetimepicker.min.css'
];
paths.scriptsVendors = [
  paths.node + '/alasql/dist/alasql.min.js',
  paths.node + '/xlsx/dist/xlsx.core.min.js',
  paths.node + '/lodash/lodash.min.js',
  paths.node + '/angular/angular.min.js',
  paths.node + '/angular-aria/angular-aria.js',
  paths.node + '/angular-animate/angular-animate.js',
  paths.node + '/angular-material/angular-material.js',
  paths.node + '/angular-material-data-table/dist/md-data-table.js',
  paths.node + '/angular1-text-mask/dist/angular1TextMask.js',
  paths.node + '/moment/min/moment.min.js',
  paths.node + '/moment/locale/pt-br.js',
  paths.node + '/angular-moment/angular-moment.min.js',
  paths.node + '/ng-material-datetimepicker/js/angular-material-datetimepicker.js',
  paths.node + '/angular-file-upload/dist/angular-file-upload.js'
];

gulp.task('scripts', function() {
  return gulp.src(paths.scripts)
    .pipe(plumber())
    .pipe(sourcemaps.init())
    .pipe(changed(paths.destination))
    .pipe(babel({
      presets: ['es2015']
    }))
    .pipe(concat(names.lib + '.js'))
    .pipe(ngAnnotate({
      add: true
    }))
    .pipe(gulp.dest(paths.destination))
    .pipe(rename(names.lib + '.min.js'))
    .pipe(uglify())
    .pipe(sourcemaps.write())
    .pipe(gulp.dest(paths.destination));
});

gulp.task('styles', function() {
  return gulp.src(paths.styles)
    .pipe(plumber())
    .pipe(sourcemaps.init())
    .pipe(changed(paths.destination))
    .pipe(sass())
    .pipe(concat(names.lib + '.css'))
    .pipe(gulp.dest(paths.destination))
    .pipe(rename(names.lib + '.min.css'))
    .pipe(cleanCSS())
    .pipe(sourcemaps.write())
    .pipe(gulp.dest(paths.destination));
});

gulp.task('vendors', function() {
  gulp.src(paths.stylesVendors)
    .pipe(plumber())
    .pipe(sourcemaps.init())
    .pipe(changed(paths.destination))
    .pipe(concat(names.lib + '-vendors.css'))
    .pipe(gulp.dest(paths.destination))
    .pipe(rename(names.lib + '-vendors.min.css'))
    .pipe(cleanCSS())
    .pipe(sourcemaps.write())
    .pipe(gulp.dest(paths.destination));

  gulp.src(paths.scriptsVendors)
    .pipe(plumber())
    .pipe(sourcemaps.init())
    .pipe(changed(paths.destination))
    .pipe(concat(names.lib + '-vendors.js'))
    .pipe(ngAnnotate({
      add: true
    }))
    .pipe(gulp.dest(paths.destination))
    .pipe(rename(names.lib + '-vendors.min.js'))
    .pipe(uglify())
    .pipe(sourcemaps.write())
    .pipe(gulp.dest(paths.destination));
});

// Rerun the task when a file changes
gulp.task('watch', function() {
  gulp.watch(paths.scripts, ['scripts']);
  gulp.watch(paths.styles, ['styles']);
});

gulp.task('check', shell.task([
  'eslint ' + paths.allScripts + ((argv.fix) ? ' --fix' : '')
], {
  ignoreErrors: true
}));

gulp.task('default', ['watch', 'scripts', 'styles', 'vendors'], function() {});
gulp.task('build', ['scripts', 'styles', 'vendors'], function() {});

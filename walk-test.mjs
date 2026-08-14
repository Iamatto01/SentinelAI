import { walkProjects } from './src/folder-walker.js';
const folders = [
  { dir: '/home/kali/FMS/Aziz', prefix: 'Aziz' },
  { dir: '/home/kali/FMS/FE_Mobile', prefix: 'FE_Mobile' },
  { dir: '/home/kali/FMS/FE_Web', prefix: 'FE_Web' },
];
console.log('=== walkProjects with maxFiles=1000 ===');
const proj = walkProjects(folders, { maxFiles: 1000 });
console.log('returned files:', proj.files.length);
console.log('stats:', JSON.stringify(proj.stats, null, 2));
console.log('\n=== walkProjects with maxFiles=3000 ===');
const proj3 = walkProjects(folders, { maxFiles: 3000 });
console.log('returned files:', proj3.files.length);
console.log('stats:', JSON.stringify(proj3.stats, null, 2));
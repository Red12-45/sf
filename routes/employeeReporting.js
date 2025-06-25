// routes/employeeReporting.js
const express = require('express');

module.exports = function makeEmployeeRoutes({ db, isAuthenticated }) {
  const router = express.Router();

  // helper identical to the one in app.js
  const pad = n => String(n).padStart(2, '0');

  /* ─────────── EMPLOYEE REPORTING ─────────── */

  // GET /employees
  router.get('/employees', isAuthenticated, async (req, res) => {
    try {
      const accountId = req.session.user.accountId;
      const [reportsSnap, employeesSnap] = await Promise.all([
        db.collection('employeeReports')
          .where('accountId','==',accountId)
          .orderBy('reportDate','desc')
          .get(),
        db.collection('employees')
          .where('accountId','==',accountId)
          .orderBy('name','asc')
          .get()
      ]);
      const reports   = reportsSnap.docs.map(d=>({ id:d.id, ...d.data() }));
      const employees = employeesSnap.docs.map(d=>({ id:d.id, ...d.data() }));
      res.render('employees', { reports, employees });
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  // POST /employee/checkin
  router.post('/employee/checkin', isAuthenticated, async (req, res) => {
    try {
      const { employeeId, reportTime, reportDate } = req.body;
      const accountId = req.session.user.accountId;
      const existing = await db.collection('employeeReports')
        .where('accountId','==',accountId)
        .where('employeeId','==',employeeId)
        .where('reportDate','==',reportDate)
        .get();
      if (!existing.empty)
        return res.status(400).send('Check-in already recorded');

      const empDoc = await db.collection('employees').doc(employeeId).get();
      if (!empDoc.exists) return res.status(400).send('Employee not found');

      await db.collection('employeeReports').add({
        employeeId,
        employeeName: empDoc.data().name,
        reportTime,
        leaveTime: '',
        reportDate,
        accountId,
        createdAt: new Date()
      });
      res.redirect('/employees');
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  // POST /employee/checkout
  router.post('/employee/checkout', isAuthenticated, async (req, res) => {
    try {
      const { employeeId, leaveTime, reportDate } = req.body;
      const accountId = req.session.user.accountId;
      const snap = await db.collection('employeeReports')
        .where('accountId','==',accountId)
        .where('employeeId','==',employeeId)
        .where('reportDate','==',reportDate)
        .get();
      if (snap.empty) return res.status(400).send('No check-in record found');
      const doc = snap.docs[0];
      await doc.ref.update({ leaveTime, updatedAt: new Date() });
      res.redirect('/employees');
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  // GET /employeeReport
  router.get('/employeeReport', isAuthenticated, async (req, res) => {
    try {
      const accountId = req.session.user.accountId;
      let reportsQuery = db.collection('employeeReports')
                           .where('accountId','==',accountId)
                           .orderBy('reportDate','desc');
      const { month } = req.query;
      if (month && month.trim()) {
        const [y,m] = month.split('-');
        const startDate = `${month}-01`;
        let nextM=parseInt(m,10)+1, nextY=parseInt(y,10);
        if(nextM>12){ nextM=1; nextY++; }
        const nextMonth=`${nextY}-${pad(nextM)}-01`;
        reportsQuery = reportsQuery.where('reportDate','>=',startDate)
                                   .where('reportDate','<',nextMonth);
      }
      const snap = await reportsQuery.get();
      const reports = snap.docs.map(d=>({ id:d.id, ...d.data() }));
      res.render('employeedReport', { reports, month: month||'' });
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  // GET /create-employee
  router.get('/create-employee', isAuthenticated, async (req, res) => {
    try {
      const accountId = req.session.user.accountId;
      const snap = await db.collection('employees')
                           .where('accountId','==',accountId)
                           .orderBy('name','asc')
                           .get();
      const employees = snap.docs.map(d=>({ id:d.id, ...d.data() }));
      res.render('createEmployee', { employees });
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  // POST /create-employee
  router.post('/create-employee', isAuthenticated, async (req, res) => {
    try {
      const accountId = req.session.user.accountId;
      const { name } = req.body;
      await db.collection('employees')
              .add({ name, accountId, createdAt: new Date() });
      res.redirect('/create-employee');
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  // POST /delete-employee
  router.post('/delete-employee', isAuthenticated, async (req, res) => {
    try {
      const accountId = req.session.user.accountId;
      const { employeeId } = req.body;
      const empRef = db.collection('employees').doc(employeeId);
      const empDoc = await empRef.get();
      if (!empDoc.exists || empDoc.data().accountId !== accountId) {
        return res.status(403).send('Access denied or Employee not found');
      }
      await empRef.delete();
      res.redirect('/create-employee');
    } catch (e) {
      res.status(500).send(e.toString());
    }
  });

  /* ─────────── end EMPLOYEE REPORTING ─────────── */
  return router;
};
